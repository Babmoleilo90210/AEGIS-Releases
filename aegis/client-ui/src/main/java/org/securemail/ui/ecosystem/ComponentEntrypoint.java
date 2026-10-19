package org.securemail.ui.ecosystem;

import java.io.IOException;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;
import org.securemail.client.ecosystem.*;

/** Fixed child entry point. A desktop shortcut or a bare java invocation cannot authorize an application. */
public final class ComponentEntrypoint {
  private ComponentEntrypoint() {}
  public static void main(String[] arguments) {
    try (var installationLease = org.securemail.client.maintenance600.RuntimeLease600.running()) {
      if(arguments.length!=1)throw new IOException("Откройте приложение через главное окно АЕГИС");
      ComponentId component=ComponentId.valueOf(arguments[0]);
      var hosts=ServiceLoader.load(ComponentHost.class).stream().map(ServiceLoader.Provider::get).filter(provider->provider.supports(component)).toList();
      if(hosts.size()!=1)throw new IOException("Установленный адаптер приложения отсутствует или неоднозначен");
      ComponentHost host=hosts.getFirst();
      try(var connection=LocalIpc.connectChild(System.in,component,host::verifyAuthorization);
          var runtime=new ComponentRuntime(connection,host)) {
        host.connected(connection.channel());host.verifyStartupAuthorization(connection.lease());
        AtomicReference<IOException> protocolFailure=new AtomicReference<>();
        Thread controls=new Thread(()->{try{runtime.run();}catch(IOException e){protocolFailure.set(e);}},"aegis-component-control");
        controls.setDaemon(true);controls.start();
        try{host.run(connection.lease());}finally{host.persistQueuesAndStop();}
        if(protocolFailure.get()!=null)throw protocolFailure.get();
      }
    } catch(Exception failure) {
      // No ticket, account identifier, capability, key or raw exception enters public logs.
      System.err.println("АЕГИС: запуск приложения не подтверждён или защищённое соединение закрыто.");
      System.exit(2);
    }
  }
}
