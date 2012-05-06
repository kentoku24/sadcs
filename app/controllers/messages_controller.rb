class MessagesController < ApplicationController
  def index
    # delete old messages
    
    for message in Message.all.each
      if message.created_at < Time.now - 60*60*24
        message.destroy
      end
    end
    
#    now = Time.now
#    last = now - (now.min % 10).minutes - now.sec  ## making time 15:30:00 or something
#    before_last = last - 10.minutes
    @message  = Message.new
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

    redirect_to :messages
  end
  
end
