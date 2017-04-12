#
# Be sure to run `pod lib lint AMRSA.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'AMRSA'
  s.version          = '1.0.1'
  s.summary          = 'A Object-c lib of RSA.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
1.Generate a key pair

2.Encrypt by public key

3.decrypt by private key

4.sign by private key

5.verify by public key.
                       DESC

  s.homepage         = 'https://github.com/LiuToTo/AMRSA'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'LiuToTo' => '526902870@qq.com' }
  s.source           = { :git => 'https://github.com/LiuToTo/AMRSA.git', :tag => s.version.to_s }
  s.ios.deployment_target = '7.0'
s.ios.source_files        = 'AMRSA/Classes/include/openssl/**/*.{h,m}'
  s.ios.public_header_files = 'AMRSA/Classes/include/openssl/**/*.h'
  s.ios.header_dir          = 'openssl'
  s.ios.preserve_paths      = 'AMRSA/Classes/lib/libcrypto.a', 'AMRSA/Classes/lib/libssl.a'
  s.ios.vendored_libraries  = 'AMRSA/Classes/lib/libcrypto.a', 'AMRSA/Classes/lib/libssl.a'

end
