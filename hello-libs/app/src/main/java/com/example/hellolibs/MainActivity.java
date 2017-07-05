/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.hellolibs;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
/*
 * Simple Java UI to trigger jni function. It is exactly same as Java code
 * in hello-jni.
 */
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int i;
        TextView tv = new TextView(this);

        i = doCryptOps();
        if (i == 0) {
            tv.setText( stringFromJNI() );
        }
        else {
            tv.setText( "Failure in cryptographic operations" );
        }
        setContentView(tv);
    }
    public native String  stringFromJNI();

    public native int doCryptOps();

    static {
        System.loadLibrary("hello-libs");
        System.loadLibrary("crypto_1_0_0");
        System.loadLibrary("ssl_1_0_0");
    }

}
