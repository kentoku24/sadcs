class MessagesController < ApplicationController
  def index
    # find last 10 min
    now = Time.now
    last = now - (now.min % 10).minutes - now.sec  ## making time 15:30:00 or something
    before_last = last - 10.minutes
    @message  = Message.new
	#@messages = Message.order("mixnum").where("created_at > ? AND created_at < ?", before_last, last )
	@messages = Message.order("mixnum");
	respond_to do |format|
      format.html # index.html.erb
      format.json { render json: @messages }
      format.xml { render :layout => false }
	end
  end
  
  
  def create
    num = rand(100)
    @message = Message.new(params[:message])
    @message.mixnum = num
    @message.save
    
    
    #for debugging code
    if @message.username == 'clear table'
      for message in Message.all.each
        message.destroy
      end      
    end
    #end debugging

	# generate random number of junk messages
	num = rand(5)
	#for i in (0..num)
	#  temp = Message.new()
	#  temp.username = 'RandomUserB' + i.to_s()
	#  temp.body     = 'RandomBodyB' + i.to_s()
	#  temp.mixnum   = rand(100)
	#  temp.save
	#end

    redirect_to :messages
    # delete old messages
    for message in Message.all.each
      if message.created_at < Time.now - 60*60*24
        message.destroy
      end
    end
  end
  
end
