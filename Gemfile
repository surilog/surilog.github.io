# Ruby 3.2+ 버전에서 삭제된 메서드 호환성 패치
if RUBY_VERSION >= "3.2"
  unless Object.method_defined?(:tainted?)
    class Object
      def tainted?; false; end
      def taint; self; end
      def untaint; self; end
    end
  end
end
gem "minimal-mistakes-jekyll"
source "https://rubygems.org"
# ... 이하 기존 내용 유지