package org.securemail.client.update;
import java.util.*;
import java.util.regex.*;

/** SemVer ordering; numeric prerelease identifiers never compare lexically. */
public record SemVersion(int major,int minor,int patch,List<String> prerelease) implements Comparable<SemVersion> {
  private static final Pattern PATTERN=Pattern.compile("(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(?:-([0-9A-Za-z.-]{1,64}))?");
  public SemVersion{prerelease=List.copyOf(prerelease);}
  public static SemVersion parse(String value){
    Matcher m=PATTERN.matcher(value);if(!m.matches())throw new IllegalArgumentException("Invalid semantic version");
    List<String> pre=m.group(4)==null?List.of():List.of(m.group(4).split("\\.",-1));
    for(String p:pre)if(p.isEmpty()||(p.matches("[0-9]+")&&p.length()>1&&p.startsWith("0")))throw new IllegalArgumentException("Invalid prerelease");
    return new SemVersion(Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),Integer.parseInt(m.group(3)),pre);
  }
  public int compareTo(SemVersion o){
    int c=Integer.compare(major,o.major);if(c==0)c=Integer.compare(minor,o.minor);if(c==0)c=Integer.compare(patch,o.patch);if(c!=0)return c;
    if(prerelease.isEmpty()||o.prerelease.isEmpty())return prerelease.isEmpty()?(o.prerelease.isEmpty()?0:1):-1;
    for(int i=0;i<Math.min(prerelease.size(),o.prerelease.size());i++){
      String a=prerelease.get(i),b=o.prerelease.get(i);boolean an=a.matches("[0-9]+"),bn=b.matches("[0-9]+");
      c=an&&bn?new java.math.BigInteger(a).compareTo(new java.math.BigInteger(b)):an?-1:bn?1:a.compareTo(b);if(c!=0)return c;
    }return Integer.compare(prerelease.size(),o.prerelease.size());
  }
}
