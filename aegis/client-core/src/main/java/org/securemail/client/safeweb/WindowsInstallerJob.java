package org.securemail.client.safeweb;

import com.sun.jna.*;
import com.sun.jna.platform.win32.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import java.io.IOException;

/** Lifetime containment for only the authenticated vendor installer and its own
 * descendants. This is not a browser sandbox or evidence of native acceptance.
 * A noninherited kill-on-close job also terminates it if the JVM crashes. */
final class WindowsInstallerJob implements AutoCloseable {
    private interface Jobs extends StdCallLibrary {
        Jobs INSTANCE=Native.load("kernel32",Jobs.class);
        HANDLE CreateJobObjectW(WinBase.SECURITY_ATTRIBUTES attributes,WString name);
        boolean SetInformationJobObject(HANDLE job,int kind,Pointer information,int size);
        boolean AssignProcessToJobObject(HANDLE job,HANDLE process);
        boolean TerminateJobObject(HANDLE job,int exitCode);
        boolean QueryInformationJobObject(HANDLE job,int kind,Pointer information,int size,IntByReference returned);
        int ResumeThread(HANDLE thread);
    }
    private final HANDLE job;
    WindowsInstallerJob()throws IOException {
        if(Native.POINTER_SIZE!=8)throw new IOException("Installer Tor Browser требует 64-разрядный процесс Windows");
        job=Jobs.INSTANCE.CreateJobObjectW(null,null);if(job==null)throw new IOException("Не удалось создать собственную группу installer");
        // Microsoft winnt.h x64: BASIC_LIMIT_INFORMATION=64, IO_COUNTERS=48,
        // four SIZE_T values=32. LimitFlags is the DWORD at offset16.
        try(Memory limits=new Memory(144)) {
            limits.clear();limits.setInt(16,0x2000); // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if(!Jobs.INSTANCE.SetInformationJobObject(job,9,limits,144)){
                Kernel32.INSTANCE.CloseHandle(job);throw new IOException("Не удалось ограничить время жизни installer");
            }
        }
    }
    void attachAndResume(HANDLE process,HANDLE thread)throws IOException {
        if(!Jobs.INSTANCE.AssignProcessToJobObject(job,process))throw new IOException("Не удалось ограничить собственный installer до запуска");
        if(Jobs.INSTANCE.ResumeThread(thread)==-1)throw new IOException("Не удалось запустить ограниченный installer");
    }
    void terminate(){Jobs.INSTANCE.TerminateJobObject(job,1);}
    boolean awaitEmpty(int maximumMillis)throws IOException {
        long deadline=System.nanoTime()+maximumMillis*1_000_000L;boolean interrupted=false;
        try(Memory info=new Memory(48)) {
            do {
                info.clear();if(!Jobs.INSTANCE.QueryInformationJobObject(job,1,info,48,null))throw new IOException("Не удалось подтвердить завершение группы installer");
                if(info.getInt(40)==0)return true;
                try{Thread.sleep(50);}catch(InterruptedException error){interrupted=true;}
            }while(System.nanoTime()<deadline);
            return false;
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    @Override public void close(){Kernel32.INSTANCE.CloseHandle(job);}
}
