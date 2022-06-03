package com.example.tcpls_app;

import static com.example.tcpls_app.AppState.getState;

import com.example.tcpls_app.*;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Adapter;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.channels.AlreadyBoundException;
import java.util.ArrayList;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {

    AppState state;

    boolean loggerOn = false;

    Spinner testSelector;

    String selectedTest;

    public String[] getLocalIpAddress() {
        ArrayList<String> arrayList = new ArrayList<>();
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && !inetAddress.isAnyLocalAddress()){// && !(inetAddress instanceof Inet6Address)) {
                        String addr = inetAddress.getHostAddress().split("%")[0];
                        if(!addr.substring(0,4).equals("fe80")){
                            arrayList.add(addr);
                        }
                    }
                }
            }
        } catch (SocketException ex) {
            Log.e("tcpls_app", ex.toString());
        }
        return arrayList.toArray(new String[0]);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String[] supportedTests = {"Choose test", "multiplexing" , "multipath","zero_rtt","simple_handshake","simple_transfer","perf","aggregation","aggregation_time"};

        state = getState();
        if(!state.loggerOn){
            state.logOn(this);
        }

        testSelector = (Spinner) findViewById(R.id.testSelection);

        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item, supportedTests);

        testSelector.setAdapter(adapter);
        testSelector.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                onItemSelectedHandler(parent, view, position, id);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });

    }



    private void onItemSelectedHandler(AdapterView<?> adapterView, View view, int position, long id) {
        Adapter adapter = adapterView.getAdapter();
        selectedTest = (String) adapter.getItem(position);
    }

    public void start_button(View view){
        if(selectedTest == null || selectedTest.equals("Choose test")){
            Alert.message(this, "Please select a test scenario");
            return;
        }
        String path = getFilesDir().toString();
        String[] IPs = getLocalIpAddress();
        Alert.message(this, "Start test " + selectedTest + " with server at " + state.serverAddr);
        int res;
        if(state.multi_path){
            res = this.run_client(state.serverAddr,state.serverAddrv6 ,state.serverPort, selectedTest, path, 1, IPs);
        } else{
            res = this.run_client(state.serverAddr,state.serverAddrv6 , state.serverPort, selectedTest, path, 0, IPs);
        }
        Alert.message(this, "Result of transfert " + res);
    }

    public void settings_button(View view){
        Intent intent = new Intent(getApplicationContext(), SettingsActivity.class);
        startActivity(intent);
    }

    static {
        System.loadLibrary("picotcpls-jni");
    }

    public native int run_client(String addr,String addrv6, String port, String test, String path, int conn_num, String[] addresses);

}