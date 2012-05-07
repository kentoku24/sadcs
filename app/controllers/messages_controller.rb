class MessagesController < ApplicationController
  def index
  
    # delete old messages after 12 hours
    for message in Message.all.each
      if message.created_at < Time.now - 60*60*12
          message.destroy
      end
    end
    
    @message  = Message.new
	  @messages = Message.order("mixnum");
	  
	  if @messages.length < 3
	    @messages = {}
	  end
	  
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
