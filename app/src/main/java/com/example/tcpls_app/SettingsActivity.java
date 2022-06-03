package com.example.tcpls_app;

import static com.example.tcpls_app.AppState.getState;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.os.Message;
import android.view.View;
import android.widget.EditText;
import android.widget.Switch;

public class SettingsActivity extends AppCompatActivity {

    EditText addr;
    EditText addrv6;
    EditText port_num;

    Switch swch;

    AppState state;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);


        state = getState();

        addr = findViewById(R.id.v4_input);
        addr.setText(state.serverAddr);

        addrv6 = findViewById(R.id.v6_input);
        addrv6.setText(state.serverAddrv6);

        port_num = findViewById(R.id.port_input);
        port_num.setText(state.serverPort);

        swch = findViewById(R.id.conn_switch);
        if(state.multi_path){
            addrv6.setVisibility(View.VISIBLE);
            swch.setChecked(true);
        } else {
            addrv6.setVisibility(View.INVISIBLE);
            swch.setChecked(false);
        }
    }

    public void check(View view){
        swch = findViewById(R.id.conn_switch);
        if(swch.isChecked()){
            addrv6.setVisibility(View.VISIBLE);
            swch.setChecked(true);
        } else {
            addrv6.setVisibility(View.INVISIBLE);
            swch.setChecked(false);
        }
    }

    public void home_button(View view){

        String changed = addr.getText().toString();

        if(changed != null && changed != ""){
            state.serverAddr = changed;
        }

        changed = addrv6.getText().toString();

        try {
            int p = Integer.parseInt(port_num.getText().toString());
            state.serverPort = port_num.getText().toString();
        } catch (Exception e){
            e.printStackTrace();
            Alert.message(this, "Something went wrong please try again !");
        }

        if(changed != null && changed != ""){
            state.serverAddrv6= changed;
        }
        if(swch.isChecked()){
            state.multi_path = true;
        } else {
            state.multi_path = false;
        }

        Intent intent = new Intent(getApplicationContext(), MainActivity.class);
        startActivity(intent);
    }

}