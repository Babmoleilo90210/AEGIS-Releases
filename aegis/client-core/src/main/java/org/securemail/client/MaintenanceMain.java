package org.securemail.client;
import org.securemail.client.storage.*;
/** Installer entry point: operates only on encrypted local files, with no network or passwords. */
public final class MaintenanceMain {
  private MaintenanceMain(){}
  public static void main(String[] args){
    try{
      if(args.length!=1||!args[0].equals("backup"))throw new IllegalArgumentException();
      ClientConfig config=ClientConfig.load(AppPaths.config());
      try(var lock=AppPaths.lock()){UpdateSupport.backup(config);}
      System.out.println("AEGIS backup complete");
    }catch(Exception failure){System.err.println("AEGIS: close the application and check local storage access before updating.");System.exit(1);}
  }
}
