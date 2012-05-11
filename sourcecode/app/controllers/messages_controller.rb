class MessagesController < ApplicationController
  def index
  
    # delete old messages after 12 hours
    for message in Message.all.each
      message.body.match(/(.{0,#{1}}$)/)
      ending = $1
      if ending != '='
          message.destroy
      end
      if message.created_at < Time.now - 60*60*12
          message.destroy
      end
    end
    
    @message  = Message.new
    @messages = Message.order("mixnum")
    @messages = @messages.paginate(:page => params[:page], :per_page => 5)
    if @messages.length < 5
    	for i in (1..(5-@messages.length))
    		temp = Message.new
    		temp.body = "JivNKWAFpYlxqoPJTdaB3czaXizl7HNgv2jCPTIzdE9VMhSPpVG/NjgAeJ0C9Z8t64N6u9wrChtSRKdsvQBM8dlsre4dHu9rIvxofOVvn4F4+YFhKjkKwiIt8hrb47Z0raJIqa2bFWlFYV7vlvbkDD60b6hEiZEF3t1sdS741VY="
    		temp.mixnum = rand(100)
    		@messages = @messages.append(temp)
    	end
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
