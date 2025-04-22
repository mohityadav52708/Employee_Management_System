// AI-powered Chatbot for HR Queries
document.addEventListener("DOMContentLoaded", () => {
    // Check if gsap is already loaded
    if (typeof gsap === "undefined") {
      console.error("GSAP (GreenSock Animation Platform) is required for animations. Please include it in your project.")
      return // Exit if GSAP is not loaded
    }
  
    // Create chatbot toggle button
    const chatbotToggle = document.createElement("div")
    chatbotToggle.className = "chatbot-toggle"
    chatbotToggle.innerHTML = "<i>💬</i>"
    document.body.appendChild(chatbotToggle)
  
    // Create chatbot container
    const chatbotContainer = document.createElement("div")
    chatbotContainer.className = "chatbot-container"
    chatbotContainer.innerHTML = `
      <div class="chatbot-header">
        <div class="chatbot-title">HR Assistant</div>
        <button class="chatbot-close">&times;</button>
      </div>
      <div class="chatbot-messages">
        <div class="message bot">Hello! I'm your HR assistant. How can I help you today?</div>
      </div>
      <div class="chatbot-input">
        <input type="text" placeholder="Type your message..." />
        <button>Send</button>
      </div>
    `
    document.body.appendChild(chatbotContainer)
  
    // Toggle chatbot
    chatbotToggle.addEventListener("click", () => {
      chatbotContainer.classList.toggle("open")
  
      if (chatbotContainer.classList.contains("open")) {
        chatbotToggle.style.display = "none"
  
        // Animate messages
        gsap.from(".message", {
          duration: 0.5,
          y: 20,
          opacity: 0,
          stagger: 0.1,
          ease: "power3.out",
        })
      }
    })
  
    // Close chatbot
    chatbotContainer.querySelector(".chatbot-close").addEventListener("click", () => {
      chatbotContainer.classList.remove("open")
      chatbotToggle.style.display = "flex"
    })
  
    // Send message
    const input = chatbotContainer.querySelector("input")
    const sendBtn = chatbotContainer.querySelector("button")
    const messagesContainer = chatbotContainer.querySelector(".chatbot-messages")
  
    function sendMessage() {
      const message = input.value.trim()
  
      if (message) {
        // Add user message
        const userMessage = document.createElement("div")
        userMessage.className = "message user"
        userMessage.textContent = message
        messagesContainer.appendChild(userMessage)
  
        // Animate user message
        gsap.from(userMessage, {
          duration: 0.5,
          x: 20,
          opacity: 0,
          ease: "power3.out",
        })
  
        // Clear input
        input.value = ""
  
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight
  
        // Simulate typing indicator
        const typingIndicator = document.createElement("div")
        typingIndicator.className = "message bot typing"
        typingIndicator.innerHTML = "<span>.</span><span>.</span><span>.</span>"
        messagesContainer.appendChild(typingIndicator)
  
        // Animate typing indicator
        gsap.to(typingIndicator.querySelectorAll("span"), {
          opacity: 0.5,
          stagger: 0.2,
          repeat: -1,
          yoyo: true,
        })
  
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight
  
        // In a real implementation, you would send the message to your Flask backend
        // For demo purposes, we'll simulate responses
  
        // Simulate API call to Flask backend
        setTimeout(() => {
          // Remove typing indicator
          typingIndicator.remove()
  
          // Process the message and get a response
          const response = processMessage(message)
  
          const botMessage = document.createElement("div")
          botMessage.className = "message bot"
          botMessage.textContent = response
  
          messagesContainer.appendChild(botMessage)
  
          // Animate bot message
          gsap.from(botMessage, {
            duration: 0.5,
            x: -20,
            opacity: 0,
            ease: "power3.out",
          })
  
          // Scroll to bottom
          messagesContainer.scrollTop = messagesContainer.scrollHeight
        }, 1500)
      }
    }
  
    sendBtn.addEventListener("click", sendMessage)
  
    input.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        sendMessage()
      }
    })
  
    // Process message and return response
    function processMessage(message) {
      message = message.toLowerCase()
  
      // Simple keyword-based responses
      if (message.includes("leave") || message.includes("vacation") || message.includes("time off")) {
        return "You currently have 15 days of annual leave remaining. To apply for leave, go to the Leave Management section and fill out the request form. Your manager will be notified automatically."
      } else if (message.includes("salary") || message.includes("pay") || message.includes("compensation")) {
        return "Your next salary payment is scheduled for the 30th of this month. Your current monthly salary is $5,000 with a performance bonus of up to 10%. For detailed salary information, please check the Payroll section."
      } else if (message.includes("benefits") || message.includes("insurance") || message.includes("health")) {
        return "Your benefits package includes health insurance, dental coverage, 401(k) matching up to 5%, and a wellness program. You can view and update your benefits selections in the Benefits section."
      } else if (message.includes("performance") || message.includes("review") || message.includes("evaluation")) {
        return "Your next performance review is scheduled for June 15th. Your last review score was 4.2/5. You can view your performance metrics and goals in the Performance section."
      } else if (message.includes("training") || message.includes("learning") || message.includes("development")) {
        return 'We have several training programs available for your role. The recommended courses for you are "Advanced Excel Skills" and "Project Management Fundamentals". Check the Learning & Development section for more options.'
      } else if (message.includes("attendance") || message.includes("time") || message.includes("hours")) {
        return "Your attendance record shows 98% punctuality this month. You've worked 160 hours with 2 hours of overtime. You can view your detailed attendance record in the Attendance section."
      } else if (message.includes("hello") || message.includes("hi") || message.includes("hey")) {
        return "Hello! How can I assist you with HR-related queries today?"
      } else if (message.includes("thank") || message.includes("thanks")) {
        return "You're welcome! Is there anything else I can help you with?"
      } else if (message.includes("bye") || message.includes("goodbye")) {
        return "Goodbye! Have a great day. Feel free to chat again if you need any assistance."
      } else {
        return `I understand you're asking about "${message}". This seems like a specific query. Would you like me to connect you with an HR representative for more detailed information?`
      }
    }
  })
  
  