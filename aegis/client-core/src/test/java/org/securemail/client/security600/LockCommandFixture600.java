package org.securemail.client.security600;

/** Actual owned-JVM command fixture. It never queries or changes a native desktop lock. */
public final class LockCommandFixture600 {
  private LockCommandFixture600(){}
  public static void main(String[] args)throws Exception{
    switch(args[0]){
      case "no"->System.out.print("no\n");
      case "large"->System.out.print("x".repeat(4096));
      case "failure"->{System.out.print("yes\n");System.exit(7);}
      case "stall"->Thread.sleep(30_000);
      case "environment"->{
        boolean safe=true;for(String key:new String[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","DBUS_SESSION_BUS_ADDRESS","JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","LD_PRELOAD","AEGIS_PASSWORD","AEGIS_TOKEN"})if(System.getenv(key)!=null)safe=false;
        safe&="unix:path=/run/dbus/system_bus_socket".equals(System.getenv("DBUS_SYSTEM_BUS_ADDRESS"));System.out.print(safe?"clear":"inherited");
      }
      default->throw new IllegalArgumentException("Fixture mode");
    }
  }
}
