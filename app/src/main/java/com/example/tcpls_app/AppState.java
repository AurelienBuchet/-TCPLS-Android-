package com.example.tcpls_app;

import android.content.Context;

public class AppState {

    private static AppState state;

    public String serverAddr;
    public String serverAddrv6;
    public String serverPort;

    public boolean loggerOn;

    public boolean multi_path;

    private AppState(){
        serverAddr = "66.70.231.126";
        //serverAddr = "192.168.0.42";

        serverAddrv6 = "2607:5300:60:4b33::ab01";
        serverPort = "4443";
        loggerOn = false;
        multi_path= true;
    }

    public void logOn(Context context){
        if(loggerOn){
            return;
        }
        if (start_logger() < 0){
            Alert.message(context, "Failed to start log process");
            return;
        }
        loggerOn = true;
        Alert.message(context, "Started log process");
    }

    public static AppState getState(){
        if(state == null){
            state = new AppState();
        }
        return state;
    }

    static {
        System.loadLibrary("picotcpls-jni");
    }

    public native int start_logger();

}
