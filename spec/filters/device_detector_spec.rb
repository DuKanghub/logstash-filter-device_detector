# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/device_detector"

describe LogStash::Filters::DeviceDetector do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        device_detector {
          source => "http_user_agent"
          target => "ua"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject).to include("message")
      expect(subject.get('message')).to eq('Hello World')
    end
  end
end
