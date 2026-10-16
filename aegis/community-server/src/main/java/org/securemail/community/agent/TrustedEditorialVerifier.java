package org.securemail.community.agent;

import java.net.URI;
import java.util.*;

/** The central model derives fresh editorial text from centrally verified source observations.
 * Worker title/summary/confidence are never passed to this independent model call. */
public final class TrustedEditorialVerifier extends CentralEvidenceVerifier {
  @FunctionalInterface public interface ModelFactory{NewsModel create(Map<String,Object>policy)throws Exception;}
  private final ModelFactory models;
  public TrustedEditorialVerifier(){super();models=TrustedEditorialVerifier::configured;}
  public TrustedEditorialVerifier(PublicSourceHttp http,ModelFactory models){super(http);this.models=models;}
  private static NewsModel configured(Map<String,Object>policy)throws Exception{String provider=AgentJson.text(policy,"provider",32),model=AgentJson.text(policy,"model",128),endpoint=AgentJson.text(policy,"endpoint",2048),ref=AgentJson.text(policy,"credentialRef",80);if(!ref.isEmpty()&&!ref.matches("AEGIS_NEWS_API_KEY_[A-Z0-9_]{1,48}"))throw new java.io.IOException("Некорректное имя секрета");String key=ref.isEmpty()?"":System.getenv(ref);if(!ref.isEmpty()&&(key==null||key.isBlank()))throw new java.io.IOException("Центральный API-секрет не настроен");return new HttpNewsModel(provider,model,URI.create(endpoint),key,(int)AgentJson.number(policy,"maxOutputTokens",128,4096));}
  @Override public AgentService.EvidenceProof verify(Map<String,Object>payload,List<Map<String,Object>>observations,Map<String,Object>draft)throws Exception{
    AgentService.EvidenceProof sourceProof=super.verify(payload,observations,draft);if(!sourceProof.verified())return sourceProof;
    Set<String>urls=new HashSet<>();for(Object url:(List<?>)draft.get("sources"))urls.add(url.toString());List<Map<String,Object>>input=new ArrayList<>();List<Integer>indices=new ArrayList<>();for(int n=0;n<observations.size();n++)if(urls.contains(observations.get(n).get("url"))){input.add(observations.get(n));indices.add(n);}
    @SuppressWarnings("unchecked")Map<String,Object>policy=(Map<String,Object>)payload.get("modelPolicy");
    try(NewsModel model=models.create(policy)){
      NewsModel.Result result=model.analyze(input);if(!result.document().keySet().equals(Set.of("candidates"))||!(result.document().get("candidates") instanceof List<?>candidates)||candidates.size()>10)throw new java.io.IOException("Некорректная центральная редакционная проверка");
      for(Object value:candidates){if(!(value instanceof Map<?,?>raw))continue;@SuppressWarnings("unchecked")Map<String,Object>candidate=new LinkedHashMap<>((Map<String,Object>)raw);if(!(candidate.get("citations")instanceof List<?> citations)||citations.size()<2||citations.size()>10)continue;List<Integer>original=new ArrayList<>();Set<Integer>seen=new HashSet<>();boolean valid=true;for(Object index:citations){if(!(index instanceof Number n)||n.doubleValue()!=n.intValue()||n.intValue()<0||n.intValue()>=indices.size()||!seen.add(n.intValue())){valid=false;break;}original.add(indices.get(n.intValue()));}if(!valid)continue;candidate.put("citations",original);
        return new AgentService.EvidenceProof(true,"CENTRAL_SOURCES_AND_EDITORIAL_MODEL",sourceProof.receipts(),candidate,result.inputTokens(),result.outputTokens());
      }
      return new AgentService.EvidenceProof(false,"CENTRAL_EDITORIAL_REVIEW_REQUIRED",sourceProof.receipts(),Map.of(),result.inputTokens(),result.outputTokens());
    }catch(Exception error){return new AgentService.EvidenceProof(false,"CENTRAL_MODEL_UNAVAILABLE_OR_INVALID",sourceProof.receipts());}
  }
}
