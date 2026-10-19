package org.aegis.android;

import android.content.*;
import android.content.pm.PackageInstaller;
import android.widget.Toast;

/** Unexported explicit PendingIntent callback; only the system installer prompts the user. */
public final class InstallResultReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c,Intent result){
        if(!AndroidPolicy.CORE.equals(c.getPackageName())||!(c.getPackageName()+".INSTALL_RESULT").equals(result.getAction()))return;
        int status=result.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE);
        if(status==PackageInstaller.STATUS_PENDING_USER_ACTION){Intent confirmation=result.getParcelableExtra(Intent.EXTRA_INTENT,Intent.class);if(confirmation!=null){confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);c.startActivity(confirmation);}return;}
        Toast.makeText(c,status==PackageInstaller.STATUS_SUCCESS?"Приложение установлено системой":"Установка не завершена. Проверьте системное сообщение",Toast.LENGTH_LONG).show();
    }
}
