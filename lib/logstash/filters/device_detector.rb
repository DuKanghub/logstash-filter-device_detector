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
      os_full = "Other"
      engine = ""
      engine_version = ""
      browser = ""
      browser_version = ""
      browser_full = ""
      os_name = ""
      os_version = ""
      device_name = ""
      device_brand = ""

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
      if data.device_brand
        device_brand = data.device_brand
      end
      if data.device_name
        device_name = data.device_name
      end
      if data.os_name && data.os_full_version
        os_name = data.os_name
        os_version = data.os_full_version
        os_full = "#{os_name} #{os_version}"
      else
        if data.os_name
          os_name = data.os_name
          os_full = os_name
        end
        if data.os_full_version
          os_version = data.os_full_version
        end
      end

      if data.name && data.full_version
        browser = data.name
        browser_version = data.full_version
        browser_full = "#{browser},#{browser_version}"
      else
        if data.name
          browser = data.name
          browser_full = browser
        end
        if data.full_version
          browser_version = data.full_version
        end
      end
      if browser =~ /firefox/i
        mozilla = true
      end

      # 构造输出哈希表
      output = {
        "isMobile" => is_mobile,
        "isBot" => is_bot,
        "mozilla" => mozilla,
        "model" => model,
        "platform" => platform,
        "os" => os_full,
        "engine" => engine,
        "engineVersion" => engine_version,
        "browser" => browser,
        "browserVersion" => browser_version
      }
      target_hash = {
        "browser" => {
          "name" => browser,
          "version" =>browser_version
        },
        "os" => {
          "name" => os_name,
          "version" => os_version
        },
        "device" => {
          "name" => device_name,
          "brand" => device_brand,
          "type" => platform
        }
      }
      if is_bot
        target_hash['bot_name'] = spider
      end
      event.set("httpUserAgentJson", output.to_json)
      event.set("os", os_full)
      event.set("browser", browser_full)
      event.set("spider", spider)
      event.set("#{@target}", target_hash)
    rescue StandardError => e
      @logger.error("Uknown error while setting device data", :exception => e, :field => @source, :event => event)
      return
    end

    filter_matched(event)
  end
end
