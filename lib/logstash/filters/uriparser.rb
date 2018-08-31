# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "addressable/uri"
require "public_suffix"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Uriparser < LogStash::Filters::Base

  config_name "uriparser"
  
  # source fields
  config :source, :validate => :string, :default => "uri"

  # target field
  config :target, :validate => :string

  # output fields
  config :fields, :validate => :array, :default => ["uri", "scheme", "host", "domain", "port", "query", "path", "user", "password", "fragment"]

  # style of query: "str", "hr" or "vr"
  # "str": "keyA=valueA&keyB=valueB&..."
  # "hr": { "keyA" => "valueA", "keyB" => "valueB", ... }
  # "vr": [ {"key" => "keyA", "value" => "valueA"}, {"key" => "keyB", "value" => "valueB"}, ... ]
  config :query_style, :validate => :string, :default => "str"

  # set key to the value of query without key
  # if true, key set "_key<NUMBER>".
  # if false, key set nil.
  # this option is valid when query_style is "vr"
  config :query_set_key_to_nokey, :validate => :boolean, :default => true

  # append values to the `tags` field when an exception is thrown
  config :tag_on_failure, :validate => :array, :default => ["_uriparserfailure"]

  public
  def register

    # fields
    @_fields = []
    @fields.each{ |f| 
      @_fields << f.to_sym
    }

    # flags
    @f_domain = @_fields.include?(:domain)
    @query_mode = @_fields.include?(:query) ? @query_style.to_sym : nil
    PublicSuffix::List.private_domains = false
  end # def register

  public
  def filter(event)
    begin
      parsed_uri = parse(event.get(@source))
      
      if @target.nil?
        parsed_uri.each{ |k,v|
          event.set(k, v)
        }
      else
        event.remove(@target)
        event.set(@target, parsed_uri)
      end

    rescue => e
      @tag_on_failure.each{|tag| event.tag(tag)}
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  private
  #------------------------------------------------------------
  def parse(value)
    case value
    when String
      uri = Addressable::URI.heuristic_parse(value)
      ret = uri.to_hash
      ret.store(:uri, value)
      ret.keep_if{ |k, v| !v.nil? && @_fields.include?(k) }
      ret.store(:domain, get_domain(uri.host)) if @f_domain
      
      # uri.query_values have unknown bug...
      # so, create query_values from query manually.
      query = uri.query
      return ret if query.nil?
      
      case @query_mode
      when :hr
        query_values = Hash.new([])
        cnt = 0
        query.split("&").each{ |kv| 
          if kv.include?("=")
            kv_elem = kv.split("=") 
            query_values.store( kv_elem[0], :value => kv_elem[1] )
          else
            query_values.store( ( @query_set_key_to_nokey ? "_key" + cnt.to_s : nil), kv )
            cnt += 1
          end
        }
        ret.store(:query, query_values)
      when :vr
        query_values = []
        cnt = 0
        query.split("&").each{ |kv| 
          if kv.include?("=")
            kv_elem = kv.split("=") 
            query_values << { :key => kv_elem[0], :value => kv_elem[1] }
          else
            query_values << { :key => ( @query_set_key_to_nokey ? "_key" + cnt.to_s : nil), :value => kv }
            cnt += 1
          end
        }
        ret.store(:query, query_values)
      end
      return ret

    when Array
      ret_values = []
      value.each { |v| ret_values << parse(v) }
      return ret_values
    when Hash
      ret_values = {}
      value.each { |k,v| ret_values[k] = parse(v) }
      return ret_values
    else
      return value
    end
  end

  # old addressable...........
  # old publicsuffix...oh!!!!! 
  # ( cause gemlock... )
  def get_domain(host)
    return PublicSuffix.parse(host).domain
    #return PublicSuffix.domain(host, ignore_private: true)
  end

end # class LogStash::Filters::Uriparser
