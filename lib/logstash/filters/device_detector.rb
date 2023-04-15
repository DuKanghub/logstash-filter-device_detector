# encoding: utf-8
require "logstash/filters/base"
require "device_detector"
require 'json'

class LogStash::Filters::DeviceDetector < LogStash::Filters::Base

  config_name "device_detector"

  config :source, :validate => :string, :default => "http_user_agent"

  config :target, :validate => :string, :default => "ua"

  config :tag_on_unknown, :validate => :array, :default => [ ]

  config :tag_on_bot, :validate => :array, :default => [ ]

  public
  def register

  end 

  public
  def filter(event)

    # Receive source
    useragent = event.get(@source)
    return if useragent.nil? || !useragent.is_a?(String) || useragent.strip == ""

    # Parse user-agent via device-detector
    begin
      data = DeviceDetector.new(useragent)
    rescue StandardError => e
      @logger.error("Uknown error while parsing device data", :exception => e, :field => @source, :event => event)
      return
    end
    return unless data

    # Remove original source (if its also the target)
    event.remove(@source) if @target == @source

    # Set all fields
    begin
      unless data.known?
        @tag_on_unknown.each { |tag| event.tag(tag) }
      end
      if data.bot?
        @tag_on_bot.each { |tag| event.tag(tag) }
      end
      is_mobile = false
      is_bot = false
      spider = ""
      mozilla = false
      model = true
      platform = "Other"
      os = "Other"
      engine = ""
      engine_version = ""
      browser = ""
      browser_version = ""

      if data.device_type =~ /phone/
        is_mobile = true
      end

      if data.bot?
        is_bot = true
        spider = data.bot_name
      end
      if data.device_type
        platform = data.device_type
      end
      if data.os_full_version
        os = "#{data.os_name} #{data.os_full_version}"
      end
      if data.name
        browser = data.name
        if data.name =~ /irefox/
          mozilla = true
        end
      end
      if data.full_version
        browser_version = data.full_version
      end
      # 构造输出哈希表
      output = {
        "isMobile" => is_mobile,
        "isBot" => is_bot,
        "mozilla" => mozilla,
        "model" => model,
        "platform" => platform,
        "os" => os,
        "engine" => engine,
        "engineVersion" => engine_version,
        "browser" => browser,
        "browserVersion" => browser_version
      }
      event.set("httpUserAgentJson", output.to_json)
      event.set("os", os)
      event.set("browser", "#{browser},#{browser_version}")
      event.set("spider", spider)
      event.set("#{@target}[browser][name]", data.name) if data.name
      event.set("#{@target}[browser][version]", data.full_version) if data.full_version
      event.set("#{@target}[os][name]", data.os_name) if data.os_name
      event.set("#{@target}[os][version]", data.os_full_version) if data.os_full_version
      event.set("#{@target}[device][name]", data.device_name) if data.device_name
      event.set("#{@target}[device][brand]", data.device_brand) if data.device_brand
      event.set("#{@target}[device][type]", data.device_type) if data.device_type
      event.set("#{@target}[bot][name]", data.bot_name) if data.bot_name
      event.set("#{@target}[bot][name]", data.bot_name) if data.bot_name
    rescue StandardError => e
      @logger.error("Uknown error while setting device data", :exception => e, :field => @source, :event => event)
      return
    end

    filter_matched(event)
  end
end
