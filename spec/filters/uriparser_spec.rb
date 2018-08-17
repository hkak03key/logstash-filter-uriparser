# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/uriparser"

describe LogStash::Filters::Uriparser do
  describe "basic" do
    let(:config) do <<-CONFIG
      filter {
        uriparser => {}
      }
    CONFIG
    end
    
  end
end
