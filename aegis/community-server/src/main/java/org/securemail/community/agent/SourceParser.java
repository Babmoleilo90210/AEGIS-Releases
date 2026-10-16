package org.securemail.community.agent;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.*;
import javax.swing.text.html.parser.ParserDelegator;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.time.format.*;
import java.util.*;

/** Extracts text, never executes active content or fetches article links/attachments. */
public final class SourceParser {
  public record Observation(String sourceId,String sourceGroup,boolean official,String cityId,String title,String text,String url,String publishedAt) {
    public Map<String,Object> map(){return Map.of("sourceId",sourceId,"sourceGroup",sourceGroup,"official",official,"cityId",cityId,"title",title,"text",text,"url",url,"publishedAt",publishedAt);}
  }
  public List<Observation> parse(String sourceId,String group,boolean official,String city,URI source,String contentType,byte[] bytes)throws IOException{
    if(bytes.length>1_000_000)throw new IOException("Источник слишком большой");
    String type=contentType.toLowerCase(Locale.ROOT);if(type.contains("xml")||type.contains("rss")||type.contains("atom"))return feed(sourceId,group,official,city,source,bytes);
    if(type.startsWith("text/html")){Html h=html(new String(bytes,StandardCharsets.UTF_8),24000);if(h.title.isBlank()||h.body.isBlank())return List.of();return List.of(new Observation(sourceId,group,official,city,h.title,h.body,source.toString(),h.date));}
    throw new IOException("Формат источника не поддерживается");
  }
  private List<Observation> feed(String id,String group,boolean official,String city,URI source,byte[] bytes)throws IOException{
    try{
      DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);f.setXIncludeAware(false);f.setExpandEntityReferences(false);f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);f.setFeature("http://xml.org/sax/features/external-general-entities",false);f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
      var builder=f.newDocumentBuilder();builder.setEntityResolver((publicId,systemId)->{throw new IOException("Внешние XML-сущности запрещены");});builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler(){@Override public void fatalError(org.xml.sax.SAXParseException e)throws org.xml.sax.SAXException{throw e;}});
      Document document=builder.parse(new InputSource(new ByteArrayInputStream(bytes)));List<Element> entries=new ArrayList<>();walkEntries(document.getDocumentElement(),entries,0,new int[]{0});List<Observation> result=new ArrayList<>();
      for(Element entry:entries){String title=plain(child(entry,"title"),300);String text=plain(first(entry,"description","summary","content","encoded"),24000);String date=normalizeDate(first(entry,"pubDate","published","updated","date"));String link=child(entry,"link");if(link.isBlank()){NodeList links=entry.getElementsByTagNameNS("*","link");for(int n=0;n<links.getLength();n++){Element el=(Element)links.item(n);if(el.getAttribute("rel").isBlank()||el.getAttribute("rel").equals("alternate")){link=el.getAttribute("href");break;}}}URI uri;try{uri=source.resolve(link);}catch(IllegalArgumentException e){continue;}if(!safeMetadataUrl(uri)||title.isBlank()||text.isBlank())continue;result.add(new Observation(id,group,official,city,title,text,uri.toString(),date));}
      return List.copyOf(result);
    }catch(javax.xml.parsers.ParserConfigurationException|org.xml.sax.SAXException e){throw new IOException("Недопустимый XML источника",e);}
  }
  private static void walkEntries(Element e,List<Element> out,int depth,int[] count)throws IOException{if(depth>32||++count[0]>12000)throw new IOException("XML источника слишком сложный");String name=e.getLocalName()==null?e.getTagName():e.getLocalName();if(name.equals("entry")||name.equals("item")){if(out.size()>=100)throw new IOException("Слишком много публикаций в источнике");out.add(e);return;}for(Node n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element child)walkEntries(child,out,depth+1,count);}
  private static String first(Element e,String...keys){for(String k:keys){String s=child(e,k);if(!s.isBlank())return s;}return "";}
  private static String child(Element e,String key){for(Node n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element c){String name=c.getLocalName()==null?c.getTagName():c.getLocalName();if(name.equals(key))return c.getTextContent();}return "";}
  public static boolean safeMetadataUrl(URI uri){return "https".equalsIgnoreCase(uri.getScheme())&&uri.getHost()!=null&&uri.getRawUserInfo()==null&&uri.getRawFragment()==null&&uri.toString().length()<=2048;}
  public static String normalizeDate(String date){if(date==null||date.length()>100)return "";try{return Instant.parse(date.trim()).toString();}catch(DateTimeParseException ignored){}try{return OffsetDateTime.parse(date.trim()).toInstant().toString();}catch(DateTimeParseException ignored){}try{return ZonedDateTime.parse(date.trim(),DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toString();}catch(DateTimeParseException ignored){}try{return LocalDate.parse(date.trim()).atStartOfDay(ZoneOffset.UTC).toInstant().toString();}catch(DateTimeParseException ignored){}return "";}
  private static String plain(String s,int max)throws IOException{return html(s,max).body;}
  private static final class Html {String title="",body="",date="";}
  private static Html html(String input,int max)throws IOException{
    Html result=new Html();StringBuilder body=new StringBuilder(),title=new StringBuilder();new ParserDelegator().parse(new StringReader(input),new HTMLEditorKit.ParserCallback(){int suppressed,titleDepth;
      @Override public void handleStartTag(HTML.Tag tag,MutableAttributeSet attrs,int pos){if(tag==HTML.Tag.SCRIPT||tag==HTML.Tag.STYLE)suppressed++;if(tag==HTML.Tag.TITLE)titleDepth++;}
      @Override public void handleEndTag(HTML.Tag tag,int pos){if((tag==HTML.Tag.SCRIPT||tag==HTML.Tag.STYLE)&&suppressed>0)suppressed--;if(tag==HTML.Tag.TITLE&&titleDepth>0)titleDepth--;}
      @Override public void handleSimpleTag(HTML.Tag tag,MutableAttributeSet attrs,int pos){if(tag==HTML.Tag.META){String property=Objects.toString(attrs.getAttribute("property"),Objects.toString(attrs.getAttribute(HTML.Attribute.NAME),""));if(property.equals("article:published_time")||property.equals("date")){String parsed=normalizeDate(Objects.toString(attrs.getAttribute(HTML.Attribute.CONTENT),""));if(!parsed.isEmpty())result.date=parsed;}}}
      @Override public void handleText(char[] text,int pos){if(suppressed>0)return;StringBuilder target=titleDepth>0?title:body;int limit=titleDepth>0?300:max;if(target.length()<limit){if(!target.isEmpty())target.append(' ');target.append(text,0,Math.min(text.length,Math.max(0,limit-target.length())));}}
    },true);result.title=title.toString().replaceAll("\\s+"," ").strip();result.body=body.toString().replaceAll("\\s+"," ").strip();return result;
  }
}
