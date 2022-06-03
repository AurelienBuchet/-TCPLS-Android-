/**
 * \file rsched.c
 *
 * \brief Hold implementations for multi connection schedulers which the
 * receiver can set to process bytes from the different connections
 */

#include "rsched.h"

/**
 * Simply call recv once on every available socket.
 *
 * data is whatever data structure the application may want to remember and use
 * 
 * returns TCPLS_OK, TCPLS_HOLD_DATA_TO_READ or
 * TCPLS_HOLD_OUT_OF_ORDER_DATA_TO_READ.
 * or -1 upon error
 */

int round_robin_con_scheduler(tcpls_t *tcpls, fd_set *rset, tcpls_buffer_t
    *buf, void *data) {
  connect_info_t *con;
  int rret = 0;
  for (int i = 0; i < tcpls->connect_infos->size; i++) {
    int ret;
    con =  connection_get(tcpls, i);
    if (FD_ISSET(con->socket, rset) && con->state >= CONNECTED) {
      ret = recv(con->socket, tcpls->recvbuf, tcpls->recvbuflen, 0);
      ret = tcpls_internal_data_process(tcpls, con, ret, buf);
      if (ret < 0)
        return ret;
      else if (rret == TCPLS_OK && rret > TCPLS_OK)
        rret = ret;
    }
  }
  return rret;
}
