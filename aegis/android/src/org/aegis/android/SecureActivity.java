package org.aegis.android;

import android.app.Activity;
import android.content.*;
import android.os.*;
import android.view.*;

public abstract class SecureActivity extends Activity {
    protected final Handler ui=new Handler(Looper.getMainLooper());
    private final BroadcastReceiver screen=new BroadcastReceiver(){@Override public void onReceive(Context c,Intent i){if(Intent.ACTION_SCREEN_OFF.equals(i.getAction())){if(AndroidPolicy.CORE.equals(getPackageName())){SessionLedger.get(c).lock();CoreBrokerService.revoked();}locked();}}};
    @Override protected void onCreate(Bundle state){super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);setRecentsScreenshotEnabled(false);getWindow().setHideOverlayWindows(true);registerReceiver(screen,new IntentFilter(Intent.ACTION_SCREEN_OFF),Context.RECEIVER_NOT_EXPORTED);}
    @Override public boolean dispatchTouchEvent(MotionEvent event){if((event.getFlags()&(MotionEvent.FLAG_WINDOW_IS_OBSCURED|MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED))!=0)return false;if(AndroidPolicy.CORE.equals(getPackageName()))SessionLedger.get(this).touch();return super.dispatchTouchEvent(event);}
    @Override protected void onDestroy(){unregisterReceiver(screen);ui.removeCallbacksAndMessages(null);super.onDestroy();}
    protected abstract void locked();
}
