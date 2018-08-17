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
  
  # source and target fields
  config :source, :validate => :string, :default => "uri"

  config :target, :validate => :string

  # output fields
  # "query_values" IS NOT RUNNING.
  config :fields, :validate => :array, :default => ["uri", "scheme", "host", "domain", "port", "query", "query_values", "path", "user", "password", "fragment"]

  # style of query_values: "vr" or "hr" 
  # NOT RUNNING.
  config :query_values_style, :validate => :string, :default => "hr"

  # append values to the `tags` field when an exception is thrown
  config :tag_on_failure, :validate => :array, :default => ["_uriparserfailure"]

  public
  def register
    # target
    if @target.nil?
      @target = @source
    end

    # fields
    @_fields = []
    @fields.each{ |f| 
      @_fields << f.to_sym
    }

    # flags
    @f_domain = @_fields.include?(:domain)
    @query_values_mode = @_fields.include?(:query_values) ? @query_values_style.to_sym : nil
    PublicSuffix::List.private_domains = false
  end # def register

  public
  def filter(event)
    begin
      parsed_uri = parse(event.get(@source))
      event.remove(target)
      event.set(target, parsed_uri)
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
      
      #### unknown bug...failed to index to amazon es.
      # query_values = uri.query_values
      # unless query_values.nil?
      #   case @query_values_mode
      #   when :hr
      #     ret.store(:query_values, query_values)
      #   when :vr
      #     query_values_vr = []
      #     query_values.each{ |k,v| query_values_vr << { :key => k, :value => v } }
      #     ret.store(:query_values, query_values_vr)
      #     logger.debug( "query_values", :query_values => query_values, :query_values_vr => query_values_vr )
      #   end
      # end
      #
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
