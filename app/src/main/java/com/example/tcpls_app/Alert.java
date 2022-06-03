package com.example.tcpls_app;

import android.content.Context;
import android.widget.Toast;

/**
 * Cette classe sert à afficher un message qui va se superposer à l'activité en cours.
 */
public class Alert {
    public static void message(Context context, String message) {
        Toast.makeText(context, message, Toast.LENGTH_LONG).show();
    }
}
