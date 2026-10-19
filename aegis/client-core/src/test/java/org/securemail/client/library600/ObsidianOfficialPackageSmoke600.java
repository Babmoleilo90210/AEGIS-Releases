package org.securemail.client.library600;
import java.nio.file.*;
import java.net.URI;
import java.util.*;
/** Explicit developer evidence utility: real official package extraction and hash verification,
 * NOT a Tor download or native Obsidian launch test. No third-party binary is included in release artifacts. */
public final class ObsidianOfficialPackageSmoke600 {
 public static void main(String[]args)throws Exception {
  if(args.length!=2)throw new IllegalArgumentException("official downloaded tarball, new extraction directory");
  Path archive=Path.of(args[0]),dest=Path.of(args[1]);var release=new ObsidianDistribution600.Release("1.14.4",URI.create("https://github.com/obsidianmd/obsidian-releases/releases/download/v1.14.4/obsidian-1.14.4.tar.gz"),131209322,"e70b7cd63787e7f798a84fec453f5c446b91877bd3f612e8fb98e9b76cc81120");
  var d=ObsidianDistribution600.install(release,dest,()->false,(r,target,cancel)->Files.copy(archive,target));d.verify();ObsidianDistribution600.reopenLinux(dest,release,d.receiptSha256()).verify();
  System.out.println("REAL_OFFICIAL_ARCHIVE_EXTRACT_PASS version="+d.version()+" receiptSHA256="+d.receiptSha256());
  System.out.println("NATIVE_OBSIDIAN_NOT_RUN; TOR_DOWNLOAD_NOT_RUN; SOURCE_OFFICIAL_HTTPS_GITHUB_AND_API_ASSET_DIGEST");
 }
}
