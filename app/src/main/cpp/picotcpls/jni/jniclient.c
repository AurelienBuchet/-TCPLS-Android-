/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#if PICOTLS_USE_BROTLI
#include "brotli/decode.h"
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"
#if PICOTLS_USE_BROTLI
#include "picotls/certificate_compression.h"
#endif
#include "t/util.h"
#include <android/log.h>
#include <jni.h>


/* sentinels indicating that the endpoint is in benchmark mode */
static const char input_file_is_benchmark[] = "is:benchmark";

float time_diff(struct timeval *start, struct timeval *end){
    return (end->tv_sec - start->tv_sec) + 1e-6*(end->tv_usec - start->tv_usec);
}

static void shift_buffer(ptls_buffer_t *buf, size_t delta)
{
  if (delta != 0) {
    assert(delta <= buf->off);
    if (delta != buf->off)
      memmove(buf->base, buf->base + delta, buf->off - delta);
    buf->off -= delta;
  }
}

typedef enum integration_test_t {
  T_NOTEST,
  T_MULTIPATH,
  T_SIMPLE_TRANSFER,
  T_SIMPLE_HANDSHAKE,
  T_ZERO_RTT_HANDSHAKE,
  T_PERF,
  T_AGGREGATION,
  T_AGGREGATION_TIME, /* same as aggregation, but timing to add a stream is controled by a timer rather than a number of bytes */
  T_MULTIPLEXING
} integration_test_t;

struct tcpls_options {
  int timeoutval;
  unsigned int timeout;
  unsigned int is_second;
  unsigned int failover_enabled;
  list_t *our_addrs;
  list_t *our_addrs6;
  list_t *peer_addrs;
  list_t *peer_addrs6;
};

struct conn_to_tcpls {
  int state;
  int conn_fd;
  int transportid;
  unsigned int is_primary : 1;
  streamid_t streamid;
  tcpls_buffer_t *recvbuf;
  int buf_off_val; /* remember the value before read */
  unsigned int wants_to_write : 1;
  tcpls_t *tcpls;
  unsigned int to_remove : 1;
};

struct cli_data {
  list_t *socklist;
  list_t *streamlist;
  list_t *socktoremove;
  const char *goodputfile;
  struct timeval timer;
};

static struct tcpls_options tcpls_options;


static void sig_handler(int signo) {
  if (signo == SIGPIPE) {
    fprintf(stderr, "Catching a SIGPIPE error\n");
  }
}

static struct timeval timediff(struct timeval *t_current, struct timeval *t_init) {
  struct timeval diff;

  diff.tv_sec = t_current->tv_sec - t_init->tv_sec;
  diff.tv_usec = t_current->tv_usec - t_init->tv_usec;

  if (diff.tv_usec < 0) {
    diff.tv_usec += 1000000;
    diff.tv_sec--;
  }
  return diff;
}

/** Simplistic joining procedure for testing */
static int handle_mpjoin(tcpls_t *tcpls, int socket, uint8_t *connid, uint8_t *cookie, uint32_t
    transportid, void *cbdata) {
  printf("Wooh, we're handling a mpjoin\n");
  list_t *conntcpls = (list_t*) cbdata;
  struct conn_to_tcpls *ctcpls;
  struct conn_to_tcpls *ctcpls2;
  for (int i = 0; i < conntcpls->size; i++) {
    ctcpls = list_get(conntcpls, i);
    if (!memcmp(ctcpls->tcpls->connid, connid, CONNID_LEN)) {
      for (int j = 0; j < conntcpls->size; j++) {
        ctcpls2 = list_get(conntcpls, j);
        if (ctcpls2->tcpls == tcpls) {
          // HUNT BUG later! => you cannot free it now, since
          // we still need tcpls->tls to finish the handshake
          /*tcpls_free(ctcpls2->tcpls);*/
          ctcpls2->tcpls = ctcpls->tcpls;
        }
      }
      int ret = tcpls_accept(ctcpls->tcpls, socket, cookie, transportid);
      if (ctcpls->tcpls->enable_failover && ctcpls->tcpls->tls->is_server && ret >= 0) {
        tcpls_send_tcpoption(ctcpls->tcpls, ret, USER_TIMEOUT, 1);
      }
      return 0;
    }
  }
  return -1;
}

static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  struct timeval now;
  struct tm *tm;
  gettimeofday(&now, NULL);
  tm = localtime(&now.tv_sec);
  char timebuf[32], usecbuf[7];
  strftime(timebuf, 32, "%H:%M:%S", tm);
  strcat(timebuf, ".");
  sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
  strcat(timebuf, usecbuf);
  fprintf(stderr, "%s Stream event %d\n", timebuf, event);
  switch (event) {
    case STREAM_NETWORK_RECOVERED:
      fprintf(stderr, "Handling STREAM_NETWORK_RECOVERED callback\n");
      list_add(data->streamlist, &streamid);
      break;
    case STREAM_OPENED:
      fprintf(stderr, "Handling STREAM_OPENED callback\n");
      list_add(data->streamlist, &streamid);
      break;
    case STREAM_NETWORK_FAILURE:
      fprintf(stderr, "Handling STREAM_NETWORK_FAILURE callback, removing stream %u\n", streamid);
      list_remove(data->streamlist, &streamid);
      break;
    case STREAM_CLOSED:
      printf("time spent: %0.8f sec\n",time_diff(&(data->timer), &now));
      fprintf(stderr, "Handling STREAM_CLOSED callback, removing stream %u\n", streamid);
      list_remove(data->streamlist, &streamid);
      break;
    default: break;
  }
  return 0;
}

static int handle_client_connection_event(tcpls_t *tcpls, tcpls_event_t event,
    int socket, int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  struct timeval now;
  struct tm *tm;
  gettimeofday(&now, NULL);
  tm = localtime(&now.tv_sec);
  char timebuf[32], usecbuf[7];
  strftime(timebuf, 32, "%H:%M:%S", tm);
  strcat(timebuf, ".");
  sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
  strcat(timebuf, usecbuf);
  fprintf(stderr, "%s Connection event %d\n", timebuf, event);
  switch (event) {
    case CONN_FAILED:
      fprintf(stderr, "Received a CONN_FAILED on socket %d\n", socket);
      break;
    case CONN_CLOSED:
      fprintf(stderr, "Received a CONN_CLOSED; marking socket %d to remove\n", socket);
      list_add(data->socktoremove, &socket);
      break;
    case CONN_OPENED:
      fprintf(stderr, "Received a CONN_OPENED; adding the socket %d\n", socket);
      list_add(data->socklist, &socket);
      /*If we get a CON_CLOSED, then a CON_OPENED on the same sock value, we
       * need to remove the socket from the socktoremove list xD*/
      list_remove(data->socktoremove, &socket);
      break;
    default: break;
  }
  return 0;
}

/** Temporaly to ease devopment. Later on: merge with handle_connection and make
 * TCPLS supports TLS 1.3's integration tests */

static void tcpls_add_ips(tcpls_t *tcpls, struct sockaddr_storage *sa_our,
    struct sockaddr_storage *sa_peer, int nbr_our, int nbr_peer) {
  int settopeer = tcpls->tls->is_server;
  for (int i = 0; i < nbr_our; i++) {
    if (sa_our[i].ss_family == AF_INET)
      tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&sa_our[i], 1, settopeer, 1);
    else
      tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&sa_our[i], 0, settopeer, 1);
  }
  int is_primary = 0;
  for (int i = 0; i < nbr_peer; i++) {
    if (sa_peer[i].ss_family == AF_INET) {
      if (i == nbr_peer-1)
        is_primary = 1;
      else
        is_primary = 0;
      tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&sa_peer[i], is_primary, 0, 0);
    }
    else
      tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&sa_peer[i], 0, 0, 0);
  }
}

static int handle_tcpls_read(tcpls_t *tcpls, int socket, tcpls_buffer_t *buf, list_t *streamlist, list_t *conn_tcpls) {

  int ret;
  if (!ptls_handshake_is_complete(tcpls->tls) && tcpls->tls->state <
      PTLS_STATE_SERVER_EXPECT_FINISHED) {
    ptls_handshake_properties_t prop = {NULL};
    memset(&prop, 0, sizeof(prop));
    prop.received_mpjoin_to_process = &handle_mpjoin;
    prop.socket = socket;
    if (tcpls->enable_failover && tcpls->tls->is_server) {
      tcpls_set_user_timeout(tcpls, 0, 250, 0, 1, 1);
    }
    if ((ret = tcpls_handshake(tcpls->tls, &prop)) != 0) {
      if (ret == PTLS_ERROR_HANDSHAKE_IS_MPJOIN) {
        return ret;
      }
      fprintf(stderr, "tcpls_handshake failed with ret %d\n", ret);
    }
    else if (ret == 0 && tcpls->tls->is_server) {
      // set this conn as primary
      return -2;
    }
    return 0;
  }
  struct timeval timeout;
  memset(&timeout, 0, sizeof(timeout));
  int *init_sizes;
  if (tcpls->tls->is_server) {
    init_sizes = calloc(conn_tcpls->size, sizeof(int));
  }
  else {
    init_sizes = calloc(streamlist->size ? streamlist->size : 1, sizeof(int));
  }
  if (buf->bufkind == AGGREGATION)
    init_sizes[0] = buf->decryptbuf->off;
  else {
    streamid_t *streamid;
    ptls_buffer_t *decryptbuf;
    if (!tcpls->tls->is_server) {
      for (int i = 0; i < streamlist->size; i++) {
        streamid = list_get(streamlist, i);
        decryptbuf = tcpls_get_stream_buffer(buf, *streamid);
        init_sizes[i] = decryptbuf->off;
      }
    }
    else {
      /*server read */
      struct conn_to_tcpls *conn;
      for (int i = 0; i < conn_tcpls->size; i++) {
        conn = list_get(conn_tcpls, i);
        if (conn->tcpls == tcpls) {
          decryptbuf = tcpls_get_stream_buffer(buf, conn->streamid);
          if (decryptbuf) {
            init_sizes[i] = decryptbuf->off;
          }
        }
      }
    }
  }
  while ((ret = tcpls_receive(tcpls->tls, buf, &timeout)) == TCPLS_HOLD_DATA_TO_READ)
    ;
  if (ret < 0) {
    fprintf(stderr, "tcpls_receive returned %d\n",ret);
  }
  if (buf->bufkind == AGGREGATION)
    ret = buf->decryptbuf->off-init_sizes[0];
  else {
    streamid_t *wtr_streamid, *streamid;
    ptls_buffer_t *decryptbuf;
    for (int i = 0; i < buf->wtr_streams->size; i++) {
      wtr_streamid = list_get(buf->wtr_streams, i);
      if (!tcpls->tls->is_server) {
        for (int j = 0; j < streamlist->size; j++) {
          streamid = list_get(streamlist, j);
          if (*wtr_streamid == *streamid) {
            decryptbuf = tcpls_get_stream_buffer(buf, *streamid);
            if (decryptbuf) {
              ret += decryptbuf->off-init_sizes[j];
              j = streamlist->size;
            }
          }
        }
      }
      else {
        struct conn_to_tcpls *conn;
        for (int j = 0; j < conn_tcpls->size; j++) {
          conn = list_get(conn_tcpls, j);
          if (conn->tcpls == tcpls && *wtr_streamid == conn->streamid) {
             decryptbuf = tcpls_get_stream_buffer(buf, *wtr_streamid);
             if (decryptbuf) {
               ret += decryptbuf->off - init_sizes[j];
               j = conn_tcpls->size;
             }
          }
        }
      }
    }
  }
  return ret;
}

static int handle_client_perf_test(tcpls_t *tcpls, struct cli_data *data) {
  int ret;
  size_t total_recvd = 0;
  struct timespec start_time;
  ptls_handshake_properties_t prop = {NULL};

  clock_gettime(CLOCK_MONOTONIC, &start_time);
  tcpls_buffer_t *recvbuf = tcpls_stream_buffers_new(tcpls, 1);
  if (handle_tcpls_read(tcpls, 0, recvbuf, data->streamlist, NULL) < 0) {
    ret = -1;
    goto Exit;
  }


  /////////// CONNECT
  /*
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    int err = tcpls_connect(tcpls->tls, NULL, (struct sockaddr*) &tcpls->v4_addr_llist->addr, &timeout);

    if (err) {
      fprintf(stderr, "2nd tcpls_connect failed with err %d\n", err);
      return 1;
    }*/

  ////////// CONNECT

  /////////////// JOIN

  int socket = 0;
  connect_info_t *con = NULL;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    con = list_get(tcpls->connect_infos, i);
    if (con->state < JOINED) {
      socket = con->socket;
      prop.socket = socket;
      prop.client.transportid = con->this_transportid;
      prop.client.mpjoin = 1;
      /** Make a tcpls mpjoin handshake */
      int ret;

      ret = tcpls_handshake(tcpls->tls, &prop);
      if (!ret) {
        /** Create a stream on the new connection */
        if (con->dest && con->src)
          tcpls_stream_new(tcpls->tls, (struct sockaddr*) &con->src->addr, (struct sockaddr*)
              &con->dest->addr);
        else if (con->dest)
          tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
              &con->dest->addr);
        else if (con->dest6 && con->src6)
          tcpls_stream_new(tcpls->tls, (struct sockaddr*) &con->src6->addr, (struct sockaddr*)
              &con->dest6->addr);
        else
          tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
              &con->dest6->addr);
        struct timeval now;
        struct tm *tm;
        gettimeofday(&now, NULL);
        tm = localtime(&now.tv_sec);
        char timebuf[32], usecbuf[7];
        strftime(timebuf, 32, "%H:%M:%S", tm);
        strcat(timebuf, ".");
        sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
        strcat(timebuf, usecbuf);
        fprintf(stderr, "%s Sending a STREAM_ATTACH on the new path\n", timebuf);
        ret = tcpls_streams_attach(tcpls->tls, 0, 1);
        if (ret < 0) {
          fprintf(stderr, "Attaching stream failed %d\n", ret);
          perror("Attaching stream failed");
        }
      }
    }
  }

   //////////////// JOIN

  printf("Downloading!\n");
  fd_set readfds, writefds, exceptfds;

  while (1) {
    /*cleanup*/
    int *socket;
    for (int i = 0; i < data->socktoremove->size; i++) {
      socket = list_get(data->socktoremove, i);
      list_remove(data->socklist, socket);
    }
    list_clean(data->socktoremove);
    if (data->socklist->size == 0)
      goto Exit;
    int maxfds = 0;
    do {
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);
      FD_ZERO(&exceptfds);
      for (int i = 0; i < data->socklist->size; i++) {
        socket = list_get(data->socklist, i);
        FD_SET(*socket, &readfds);
        if (maxfds <= *socket)
          maxfds = *socket;
      }
    } while (select(maxfds+1, &readfds, &writefds, &exceptfds, NULL) == -1);

    int ret;
    for (int i = 0; i < data->socklist->size; i++) {
      socket = list_get(data->socklist, i);
      if (FD_ISSET(*socket, &readfds)) {
        if ((ret = handle_tcpls_read(tcpls, *socket, recvbuf, data->streamlist, NULL)) < 0) {
          fprintf(stderr, "handle_tcpls_read returned %d\n",ret);
          break;
        }
      }
      ptls_buffer_t *buf;
      streamid_t *streamid;
      for (int i = 0; i < recvbuf->wtr_streams->size; i++) {
        streamid = list_get(recvbuf->wtr_streams, i);
        buf = tcpls_get_stream_buffer(recvbuf, *streamid);
        total_recvd += buf->off;
        buf->off = 0;// blackhole the received data
      }
    }
  }
Exit: {
  struct timespec end_time;
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  double duration = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
  double goodput = (double) total_recvd * 8 / duration / 1000000.0;
  fprintf(stderr, "Received %ld bytes over %0.3f seconds, goodput is %0.3f Mbit/s\n", total_recvd, duration, goodput);
  tcpls_buffer_free(tcpls, recvbuf);
}
  return ret;
}

static int handle_client_transfer_test(tcpls_t *tcpls, int test, struct cli_data *data, const char *filePath, int multi_conn) {
  /** handshake*/
  struct timeval t_init, t_now;
  gettimeofday(&t_init, NULL);
  int ret;
  tcpls_buffer_t *recvbuf = tcpls_aggr_buffer_new(tcpls);
  FILE *mtest = fopen(strcat(filePath, "/multipath_test.data"), "w");
  assert(mtest);
  if (handle_tcpls_read(tcpls, 0, recvbuf, data->streamlist, NULL) < 0) {
    ret = -1;
    goto Exit;
  }
  printf("Handshake done\n");

  fd_set readfds, writefds, exceptfds;
  int has_migrated = 0;
  int has_remigrated = 0;
  int has_multipath =0;
  int n_streams =1;
  int received_data = 0;
  int mB_received = 0;
  struct timeval timeout;
  ptls_handshake_properties_t prop = {NULL};
  FILE *outputfile = NULL;
  if (data->goodputfile) {
    outputfile = fopen(data->goodputfile, "a");
  }

  gettimeofday(&(data->timer), NULL);

  while (1) {
    /*cleanup*/
    int *socket;
    for (int i = 0; i < data->socktoremove->size; i++) {
      socket = list_get(data->socktoremove, i);
      list_remove(data->socklist, socket);
    }
    list_clean(data->socktoremove);
    if (data->socklist->size == 0)
      goto Exit;
    int maxfds = 0;
    do {
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);
      FD_ZERO(&exceptfds);
      for (int i = 0; i < data->socklist->size; i++) {
        socket = list_get(data->socklist, i);
        FD_SET(*socket, &readfds);
        if (maxfds <= *socket)
          maxfds = *socket;
      }
      timeout.tv_sec = 3600;
      timeout.tv_usec = 0;
    } while (select(maxfds+1, &readfds, &writefds, &exceptfds, &timeout) == -1);

    int ret;
    for (int i = 0; i < data->socklist->size; i++) {
      socket = list_get(data->socklist, i);
      if (FD_ISSET(*socket, &readfds)) {
        if ((ret = handle_tcpls_read(tcpls, *socket, recvbuf, data->streamlist, NULL)) < 0) {
          fprintf(stderr, "handle_tcpls_read returned %d\n",ret);
          break;
        }
        received_data += ret;
        if (received_data / 1000000 > mB_received) {
          mB_received++;
          //printf("Received %d MB\n",mB_received);
        }
        if (outputfile && ret >= 0) {
        /*
           write infos on this received data
          struct sockaddr_storage peer_sockaddr;
          struct sockaddr_storage ss;
          socklen_t sslen = sizeof(struct sockaddr_storage);
          if (getsockname(*socket, (struct sockaddr *) &ss, &sslen) < 0) {
            perror("getsockname(2) failed");
          }
          if (getpeername(*socket, (struct sockaddr *) &peer_sockaddr, &sslen) < 0) {
            perror("getpeername(2) failed");
          }
          char buf_ipsrc[INET6_ADDRSTRLEN], buf_ipdest[INET6_ADDRSTRLEN];
          if (ss.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&ss)->sin_addr, buf_ipsrc, sizeof(buf_ipsrc));
            inet_ntop(AF_INET, &((struct sockaddr_in*)&peer_sockaddr)->sin_addr, buf_ipdest, sizeof(buf_ipdest));
          }
          else {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&ss)->sin6_addr, buf_ipsrc, sizeof(buf_ipsrc));
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&peer_sockaddr)->sin6_addr, buf_ipdest, sizeof(buf_ipdest));
          }
          struct timeval now;
          struct tm *tm;
          gettimeofday(&now, NULL);
          tm = localtime(&now.tv_sec);
          char timebuf[32], usecbuf[7];
          strftime(timebuf, 32, "%H:%M:%S", tm);
          strcat(timebuf, ".");
          sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
          strcat(timebuf, usecbuf);
          fprintf(outputfile, "%s %s > %s %u\n", timebuf, buf_ipdest, buf_ipsrc, ret);
          */
        }
        break;
      }
    }
    /** consume received data */
    fwrite(recvbuf->decryptbuf->base, recvbuf->decryptbuf->off, 1, mtest);
    recvbuf->decryptbuf->off = 0;
    if (test == T_MULTIPLEXING && n_streams < multi_conn) {
        n_streams++;
        streamid_t streamid = tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
            &tcpls->v4_addr_llist->addr);
        struct timeval now;
        struct tm *tm;
        gettimeofday(&now, NULL);
        tm = localtime(&now.tv_sec);
        char timebuf[32], usecbuf[7];
        strftime(timebuf, 32, "%H:%M:%S", tm);
        strcat(timebuf, ".");
        sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
        strcat(timebuf, usecbuf);
        fprintf(stderr, "%s Sending a STREAM_ATTACH on the new path\n", timebuf);
        if (tcpls_streams_attach(tcpls->tls, 0, 1) < 0)
          fprintf(stderr, "Failed to attach stream %u\n", streamid);
    }
    if (test == T_MULTIPATH && received_data >= 4145728  && !has_remigrated) {
      has_remigrated = 1;
      /*struct timeval timeout;*/
      /*timeout.tv_sec = 5;*/
      /*timeout.tv_usec = 0;*/
      /*tcpls_connect(tcpls->tls, NULL, (struct sockaddr*) &tcpls->v4_addr_llist->addr, &timeout);*/
      /*int socket = 0;*/
      connect_info_t *con = NULL;
      for (int i = 0; i < tcpls->connect_infos->size; i++) {
        con = list_get(tcpls->connect_infos, i);
        if (con->dest) {
          break;
        }
      }
        streamid_t streamid = tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
            &tcpls->v4_addr_llist->addr);
        struct timeval now;
        struct tm *tm;
        gettimeofday(&now, NULL);
        tm = localtime(&now.tv_sec);
        char timebuf[32], usecbuf[7];
        strftime(timebuf, 32, "%H:%M:%S", tm);
        strcat(timebuf, ".");
        sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
        strcat(timebuf, usecbuf);
        fprintf(stderr, "%s Sending a STREAM_ATTACH on the new path\n", timebuf);
        if (tcpls_streams_attach(tcpls->tls, 0, 1) < 0)
          fprintf(stderr, "Failed to attach stream %u\n", streamid);
        else
          /** closing the stream id 1 */
          tcpls_stream_close(tcpls->tls, 1, 1);
      }
    gettimeofday(&t_now, NULL);
    struct timeval diff = timediff(&t_now, &t_init);
    /** We test a migration */
    if ((received_data >= 214572800 && ((test == T_MULTIPATH && !has_migrated) ||
            (test == T_AGGREGATION && !has_multipath))) || (test ==
            T_AGGREGATION_TIME && !has_multipath && diff.tv_sec >= 1)) {
      printf("Test migration\n");
      if (test == T_MULTIPATH)
        has_migrated = 1;
      else
        has_multipath = 1;
      int socket = 0;
      connect_info_t *con = NULL;
      for (int i = 0; i < tcpls->connect_infos->size; i++) {
        con = list_get(tcpls->connect_infos, i);
        if (con->state < JOINED) {
          socket = con->socket;
          prop.socket = socket;
          prop.client.transportid = con->this_transportid;
          prop.client.mpjoin = 1;
          /** Make a tcpls mpjoin handshake */
          int ret;

          ret = tcpls_handshake(tcpls->tls, &prop);
          if (1) {
            printf("after_handshake\n");
            /** Create a stream on the new connection */
            if (con->dest && con->src)
              tcpls_stream_new(tcpls->tls, (struct sockaddr*) &con->src->addr, (struct sockaddr*)
                  &con->dest->addr);
            else if (con->dest)
              tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
                  &con->dest->addr);
            else if (con->dest6 && con->src6)
              tcpls_stream_new(tcpls->tls, (struct sockaddr*) &con->src6->addr, (struct sockaddr*)
                  &con->dest6->addr);
            else
              tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr*)
                  &con->dest6->addr);
            struct timeval now;
            struct tm *tm;
            gettimeofday(&now, NULL);
            tm = localtime(&now.tv_sec);
            char timebuf[32], usecbuf[7];
            strftime(timebuf, 32, "%H:%M:%S", tm);
            strcat(timebuf, ".");
            sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
            strcat(timebuf, usecbuf);
            fprintf(stderr, "%s Sending a STREAM_ATTACH on the new path\n", timebuf);
            ret = tcpls_streams_attach(tcpls->tls, 0, 1);
            if (ret < 0) {
              fprintf(stderr, "Attaching stream failed %d\n", ret);
              perror("Attaching stream failed");
            }
            /** Close the stream on the initial connection */
            streamid_t *streamid2 = list_get(data->streamlist, 0);
            if (test == T_MULTIPATH)
              tcpls_stream_close(tcpls->tls, *streamid2, 1);
          }
        }
      }
    }
  }
  ret = 0;
Exit:
  fclose(mtest);
  if (outputfile)
    fclose(outputfile);
  tcpls_buffer_free(tcpls, recvbuf);
  return ret;
}

static int handle_client_simple_handshake(tcpls_t *tcpls, struct cli_data *data) {
  int ret;
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  struct timeval t_init, t_now;
  gettimeofday(&t_init, NULL);

  // Connect with all v4 addresses
  tcpls_v4_addr_t *add = tcpls->ours_v4_addr_llist;
  struct sockaddr* our;
  while(add){
      our = &add->addr;
      int err = tcpls_connect(tcpls->tls, our, NULL, &timeout);
      if (err){
        fprintf(stderr, "tcpls_connect failed with err %d\n", err);
        //return 1;
      }
      struct sockaddr_in *addr_in = (struct sockaddr_in *)our;
      char *s = inet_ntoa(addr_in->sin_addr);
      printf("IP address: %s\n", s);
      add = add->next;
  }

  ptls_handshake_properties_t prop = {NULL};
  prop.client.dest = (struct sockaddr_storage *) &tcpls->v4_addr_llist->addr;
  ret = tcpls_handshake(tcpls->tls, &prop);
  gettimeofday(&t_now, NULL);
  struct timeval rtt = timediff(&t_now, &t_init);
  printf("Handshake took %lu µs\n", rtt.tv_sec*1000000+rtt.tv_usec);
  return ret;
}

static int handle_client_zero_rtt_test(tcpls_t *tcpls, struct cli_data *data) {
  int ret;
  ptls_handshake_properties_t prop = {NULL};
  prop.client.zero_rtt = 1;
  if (tcpls->v4_addr_llist)
    prop.client.dest = (struct sockaddr_storage *) &tcpls->v4_addr_llist->addr;
  else
    prop.client.dest = (struct sockaddr_storage *) &tcpls->v6_addr_llist->addr;
  struct timeval t_init, t_now;
  gettimeofday(&t_init, NULL);
  ret = tcpls_handshake(tcpls->tls, &prop);
  gettimeofday(&t_now, NULL);
  struct timeval rtt = timediff(&t_now, &t_init);
  printf("Handshake took %lu µs\n", rtt.tv_sec*1000000+rtt.tv_usec);
  return ret;
}

static int handle_client_connection(tcpls_t *tcpls, struct cli_data *data,
    integration_test_t test, const char *filePath, int multi_conn) {
  int ret;
  switch (test) {
    case T_SIMPLE_HANDSHAKE:
      ret = handle_client_simple_handshake(tcpls, data);
      if (!ret)
        printf("TEST Simple Handshake: SUCCESS\n");
      else
        printf("TEST Simple Handshake: FAILURE\n");
      break;
    case T_ZERO_RTT_HANDSHAKE:
      ret = handle_client_zero_rtt_test(tcpls, data);
      if (!ret)
        printf("TEST 0-RTT: SUCCESS\n");
      else
        printf("TEST 0-RTT: FAILURE\n");
      break;
    case T_SIMPLE_TRANSFER:
    case T_MULTIPATH:
    case T_AGGREGATION:
    case T_AGGREGATION_TIME:
      {
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;


        int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout);
        if (err){
          fprintf(stderr, "tcpls_connect failed with err %d\n", err);
          return 1;
        }

        if (test == T_MULTIPATH || test == T_AGGREGATION  || test == T_AGGREGATION_TIME){
          tcpls->enable_multipath = 1;
        }
        else {
          if (tcpls->enable_failover)
            tcpls->enable_multipath = 1;
        }
        ret = handle_client_transfer_test(tcpls, test, data, filePath, multi_conn);
      }
      break;
    case T_PERF:
      {
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout);
        if (err){
          fprintf(stderr, "tcpls_connect failed with err %d\n", err);
          return 1;
        }

        if (tcpls->enable_failover) {
          tcpls->enable_multipath = 1;
        }
        ret = handle_client_perf_test(tcpls, data);
        break;
      }
    case T_MULTIPLEXING:
      {
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
          // Connect with all v4 addresses
          tcpls_v4_addr_t *add = tcpls->ours_v4_addr_llist;
          struct sockaddr* our;
          while(add){
              our = &add->addr;
              int err = tcpls_connect(tcpls->tls, our, NULL, &timeout);
              if (err){
                fprintf(stderr, "tcpls_connect failed with err %d\n", err);
                //return 1;
              }
              struct sockaddr_in *addr_in = (struct sockaddr_in *)our;
              char *s = inet_ntoa(addr_in->sin_addr);
              printf("IP address: %s\n", s);
              add = add->next;
          }
        if (tcpls->enable_failover) {
          tcpls->enable_multipath = 1;
        }
        ret = ret = handle_client_transfer_test(tcpls, test, data, filePath, multi_conn);
        break;
      }
    case T_NOTEST:
      printf("NO TEST");
      exit(1);
  }
  return 0;
}

static int run_client(struct sockaddr_storage *sa_our, struct sockaddr_storage
    *sa_peer, int nbr_our, int nbr_peer,  ptls_context_t *ctx, const char *server_name, const char
    *input_file, ptls_handshake_properties_t *hsprop, int request_key_update,
    int keep_sender_open, integration_test_t test, unsigned int failover_enabled, const char *goodputfile, const char *filePath, int multi_conn)
{
  int fd;

  hsprop->client.esni_keys = resolve_esni_keys(server_name);
  list_t *socklist = new_list(sizeof(int), 2);
  list_t *socktoremove = new_list(sizeof(int), 2);
  list_t *streamlist = new_list(sizeof(tcpls_stream_t), 2);
  struct cli_data data = {NULL};
  data.socklist = socklist;
  data.streamlist = streamlist;
  data.socktoremove = socktoremove;
  data.goodputfile = goodputfile;
  ctx->cb_data = &data;
  ctx->stream_event_cb = &handle_client_stream_event;
  ctx->connection_event_cb = &handle_client_connection_event;
  tcpls_t *tcpls = tcpls_new(ctx, 0);
  tcpls_add_ips(tcpls, sa_our, sa_peer, nbr_our, nbr_peer);
  ctx->output_decrypted_tcpls_data = 0;
  tcpls->enable_failover = failover_enabled;
  signal(SIGPIPE, sig_handler);

  if (ctx->support_tcpls_options) {
    int ret = handle_client_connection(tcpls, &data, test, filePath, multi_conn);
    free(hsprop->client.esni_keys.base);
    tcpls_free(tcpls);
    return ret;
  }
}


JNIEXPORT jint
Java_com_example_tcpls_1app_MainActivity_run_1client(JNIEnv *env, jobject thiz, jstring jaddr, jstring jaddrv6,
                                                     jstring jport, jstring jtest, jstring jpath, jint multi_conn,jobjectArray jaddr_array)
{
  const char *c_addr = (*env)->GetStringUTFChars(env, jaddr, 0);
  const char *c_addrv6 = (*env)->GetStringUTFChars(env, jaddrv6, 0);
  const char *c_port = (*env)->GetStringUTFChars(env, jport, 0);
  const char *c_test = (*env)->GetStringUTFChars(env, jtest, 0);
  const char *c_path = (*env)->GetStringUTFChars(env, jpath, 0);


  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
  /* Load all compiled-in ENGINEs */
  ENGINE_load_builtin_engines();
  ENGINE_register_all_ciphers();
  ENGINE_register_all_digests();
#endif

  res_init();

  ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
  ptls_cipher_suite_t *cipher_suites[128] = {NULL};
  ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, cipher_suites};
  ptls_handshake_properties_t hsprop = {{{{NULL}}}};
  const char *host, *port, *input_file = NULL, *esni_file = NULL, *goodputfile = NULL;
  integration_test_t test = T_NOTEST;
  struct {
    ptls_key_exchange_context_t *elements[16];
    size_t count;
  } esni_key_exchanges;
  int is_server = 0, use_early_data = 0, request_key_update = 0, keep_sender_open = 0, ch;
  /*struct sockaddr_storage sa;*/
  socklen_t salen;
  memset(&tcpls_options, 0, sizeof(tcpls_options));
  tcpls_options.our_addrs = new_list(16*sizeof(char), 2);
  tcpls_options.peer_addrs = new_list(16*sizeof(char), 2);
  tcpls_options.our_addrs6 = new_list(40*sizeof(char), 2);
  tcpls_options.peer_addrs6 = new_list(40*sizeof(char), 2);
  int family = 0;

  if (strcasecmp(c_test, "multipath") == 0)
    test = T_MULTIPATH;
  else if (strcasecmp(c_test, "zero_rtt") == 0)
    test = T_ZERO_RTT_HANDSHAKE;
  else if (strcasecmp(c_test, "simple_handshake") == 0)
    test = T_SIMPLE_HANDSHAKE;
  else if (strcasecmp(c_test, "simple_transfer") == 0)
    test = T_SIMPLE_TRANSFER;
  else if (strcasecmp(c_test, "perf") == 0)
    test = T_PERF;
  else if (strcasecmp(c_test, "aggregation") == 0)
    test = T_AGGREGATION;
  else if (strcasecmp(c_test, "aggregation_time") == 0)
    test = T_AGGREGATION_TIME;
  else if (strcasecmp(c_test, "multiplexing") == 0)
    test = T_MULTIPLEXING;
  else{
    test = T_PERF;
    printf("%s\n", "error");
  }



  int addrCount = (*env)->GetArrayLength(env, jaddr_array);

  /* char addr_server[16];
  if (strlen(c_addr) > 15)  {
      fprintf(stderr, "Uncorrect v4 addr: %s\n", c_addr);
      exit(1);
    }
    if (!tcpls_options.peer_addrs)
      tcpls_options.peer_addrs = new_list(16*sizeof(char), 2);
    memcpy(addr_server, c_addr, strlen(c_addr));
    addr_server[strlen(c_addr)] = '\0';
    list_add(tcpls_options.peer_addrs, addr_server);*/

    if(multi_conn){
        char addr_serverv6[40];
        if (strlen(c_addrv6) > 39)  {
            fprintf(stderr, "Uncorrect v6 addr: %s\n", c_addrv6);
            exit(1);
          }
          if (!tcpls_options.peer_addrs6)
            tcpls_options.peer_addrs6 = new_list(40*sizeof(char), 2);
          memcpy(addr_serverv6, c_addrv6, strlen(c_addrv6));
          addr_serverv6[strlen(c_addrv6)] = '\0';
          list_add(tcpls_options.peer_addrs6, addr_serverv6);
    }
  ctx.support_tcpls_options = 1;

  if (use_early_data) {
    static size_t max_early_data_size;
    hsprop.client.max_early_data_size = &max_early_data_size;
  }
  ctx.send_change_cipher_spec = 1;

  if (key_exchanges[0] == NULL)
    key_exchanges[0] = &ptls_openssl_secp256r1;
  if (cipher_suites[0] == NULL) {
    size_t i;
    for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
      cipher_suites[i] = ptls_openssl_cipher_suites[i];
  }

  host = c_addr;
  port = c_port;
  int nbr_our_addrs, nbr_peer_addrs, offset;
  offset = 0;
  nbr_peer_addrs = tcpls_options.peer_addrs6->size+1;

  struct sockaddr_storage sa_ours[nbr_our_addrs];
  struct sockaddr_storage sa_peer[nbr_peer_addrs];

  char *addr;
  /*
  for (int i = 0; i < tcpls_options.our_addrs->size; i++) {
    addr = list_get(tcpls_options.our_addrs, i);
    if (resolve_address((struct sockaddr *)&sa_ours[i], &salen, addr, "4200", AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }
  offset += tcpls_options.our_addrs->size;
  for (int i = 0; i < tcpls_options.our_addrs6->size; i++) {
    addr = list_get(tcpls_options.our_addrs6, i);
    char portV6[5];
    sprintf(portV6, "820%d",i);
    if (resolve_address((struct sockaddr *)&sa_ours[i+offset], &salen, addr, portV6, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }*/
  offset = 0;
  /*for (int i = 0; i < tcpls_options.peer_addrs->size; i++) {
    addr = list_get(tcpls_options.peer_addrs, i);
    if (resolve_address((struct sockaddr *)&sa_peer[i], &salen, c_addrv6, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
  }*/
  offset += tcpls_options.peer_addrs->size;
  for (int i = 0; i < tcpls_options.peer_addrs6->size; i++) {
    addr = list_get(tcpls_options.peer_addrs6, i);
    if (resolve_address((struct sockaddr *)&sa_peer[i+offset], &salen, addr, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0)
      exit(1);
    printf("Resolved address : %s\n", addr);
  }

  /**  resolve the host line -- keep it for backward compatibility */
  struct sockaddr *sockaddr_ptr;


  sockaddr_ptr = (struct sockaddr*) &sa_peer[nbr_peer_addrs-1];

  if (resolve_address(sockaddr_ptr, &salen, host, port,
        family, SOCK_STREAM, IPPROTO_TCP) != 0)
    exit(1);

  return run_client(sa_ours, sa_peer, nbr_our_addrs, nbr_peer_addrs, &ctx,
        host, input_file, &hsprop, request_key_update, keep_sender_open, test, tcpls_options.failover_enabled, goodputfile, c_path, multi_conn);
}