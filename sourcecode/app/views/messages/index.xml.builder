xml.instruct!
xml.classmethod :version => "1.0" do
  xml.author "Ken"
  xml.type "messages"
  @messages.each do | message |
    xml.item :username => message.username do
      xml.body message.body
      xml.mixnum message.mixnum
    end
  end
end