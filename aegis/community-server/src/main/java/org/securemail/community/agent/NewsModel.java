package org.securemail.community.agent;

import java.io.IOException;
import java.util.*;

/** A model only returns suggestions. Authorization and publication remain server operations. */
public interface NewsModel extends AutoCloseable {
  record Result(Map<String,Object> document,long inputTokens,long outputTokens,String provider,String model) {
    public Result{document=Map.copyOf(document);}
  }
  Result analyze(List<Map<String,Object>> publicObservations)throws IOException;
  /** Private-library calls must be explicitly routed to an administrator-approved LOCAL adapter. */
  default Result proposePrivateLinks(List<Map<String,Object>> authorizedMaterials)throws IOException{throw new IOException("Внешняя модель не обрабатывает закрытые материалы");}
  @Override default void close(){}
}
