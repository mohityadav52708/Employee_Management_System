// Enhanced Employee Dashboard JavaScript
document.addEventListener("DOMContentLoaded", () => {
    // Initialize GSAP animations
    initializeGSAPAnimations()
  
    // Setup 3D card effects
    setup3DCardEffects()
  
    // Initialize chatbot
    initializeChatbot()
  
    // Setup real-time notifications
    setupRealTimeNotifications()
  
    // Initialize parallax effects
    initializeParallaxEffects()
  })
  
  function initializeGSAPAnimations() {
    // Header animation
    gsap.from(".image h1", {
      duration: 1,
      y: -50,
      opacity: 0,
      ease: "power3.out",
    })
  
    // Sidebar animation
    gsap.from(".sidebar", {
      duration: 1,
      x: -100,
      opacity: 0,
      ease: "power3.out",
    })
  
    // Card animations with staggered effect
    gsap.from(".card", {
      duration: 0.8,
      y: 50,
      opacity: 0,
      stagger: 0.1,
      ease: "power3.out",
    })
  
    // Button animations
    gsap.from(".btn", {
      duration: 0.5,
      scale: 0.8,
      opacity: 0,
      stagger: 0.1,
      ease: "back.out(1.7)",
      delay: 1,
    })
  
    // Profile image animation
    gsap.from(".profile-section", {
      duration: 1,
      scale: 0,
      rotation: 360,
      opacity: 0,
      ease: "elastic.out(1, 0.3)",
      delay: 0.5,
    })
  
    // Scroll animations
    gsap.registerPlugin(ScrollTrigger)
  
    gsap.utils.toArray(".container").forEach((container, i) => {
      ScrollTrigger.create({
        trigger: container,
        start: "top 80%",
        end: "bottom 20%",
        onEnter: () => {
          gsap.to(container, {
            duration: 0.8,
            y: 0,
            opacity: 1,
            ease: "power3.out",
          })
        },
        onLeaveBack: () => {
          gsap.to(container, {
            duration: 0.8,
            y: 50,
            opacity: 0,
            ease: "power3.out",
          })
        },
      })
    })
  }
  
  function setup3DCardEffects() {
    // Add 3D tilt effect to cards
    const cards = document.querySelectorAll(".card")
  
    cards.forEach((card) => {
      card.addEventListener("mousemove", (e) => {
        const rect = card.getBoundingClientRect()
        const x = e.clientX - rect.left // x position within the element
        const y = e.clientY - rect.top // y position within the element
  
        const centerX = rect.width / 2
        const centerY = rect.height / 2
  
        const deltaX = ((x - centerX) / centerX) * 10 // Max 10 degrees
        const deltaY = ((y - centerY) / centerY) * 10 // Max 10 degrees
  
        card.style.transform = `perspective(1000px) rotateX(${-deltaY}deg) rotateY(${deltaX}deg) scale3d(1.02, 1.02, 1.02)`
  
        // Add dynamic shadow based on tilt
        card.style.boxShadow = `
          ${deltaX * -1}px ${deltaY * -1}px 20px rgba(0, 243, 255, 0.2),
          0 10px 20px rgba(0, 0, 0, 0.2)
        `
  
        // Add shine effect
        const shine = card.querySelector(".shine") || document.createElement("div")
        if (!card.querySelector(".shine")) {
          shine.className = "shine"
          shine.style.position = "absolute"
          shine.style.top = "0"
          shine.style.left = "0"
          shine.style.right = "0"
          shine.style.bottom = "0"
          shine.style.backgroundImage =
            "linear-gradient(135deg, rgba(255,255,255,0) 0%, rgba(255,255,255,0.1) 50%, rgba(255,255,255,0) 100%)"
          shine.style.transform = "translateZ(1px)"
          shine.style.pointerEvents = "none"
          card.style.position = "relative"
          card.style.overflow = "hidden"
          card.appendChild(shine)
        }
  
        // Position the shine based on mouse position
        const shineX = (x / rect.width) * 100
        const shineY = (y / rect.height) * 100
        shine.style.backgroundPosition = `${shineX}% ${shineY}%`
      })
  
      card.addEventListener("mouseleave", () => {
        card.style.transform = "perspective(1000px) rotateX(0) rotateY(0) scale3d(1, 1, 1)"
        card.style.boxShadow = "0 10px 20px rgba(0, 0, 0, 0.2)"
  
        const shine = card.querySelector(".shine")
        if (shine) {
          shine.style.backgroundPosition = "50% 50%"
        }
      })
    })
  
    // Add hover effect to buttons
    const buttons = document.querySelectorAll(".btn")
  
    buttons.forEach((button) => {
      button.addEventListener("mouseenter", () => {
        gsap.to(button, {
          duration: 0.3,
          backgroundColor: "#00f3ff",
          color: "#000",
          scale: 1.05,
          boxShadow: "0 0 15px rgba(0, 243, 255, 0.7)",
          ease: "power2.out",
        })
      })
  
      button.addEventListener("mouseleave", () => {
        gsap.to(button, {
          duration: 0.3,
          backgroundColor: "",
          color: "",
          scale: 1,
          boxShadow: "",
          ease: "power2.out",
        })
      })
    })
  }
  
  function initializeChatbot() {
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
  
        // Simulate bot response
        setTimeout(() => {
          // Remove typing indicator
          typingIndicator.remove()
  
          const botMessage = document.createElement("div")
          botMessage.className = "message bot"
  
          // Simple responses based on keywords
          if (message.toLowerCase().includes("leave") || message.toLowerCase().includes("vacation")) {
            botMessage.textContent =
              "To apply for leave, go to the Leave Management section. You currently have 15 days of annual leave remaining."
          } else if (message.toLowerCase().includes("salary") || message.toLowerCase().includes("pay")) {
            botMessage.textContent =
              "Your next salary payment is scheduled for the 30th of this month. For detailed salary information, please check the Payroll section."
          } else if (message.toLowerCase().includes("hello") || message.toLowerCase().includes("hi")) {
            botMessage.textContent = "Hello! How can I assist you with HR-related queries today?"
          } else {
            botMessage.textContent =
              "I understand you're asking about \"" +
              message +
              '". Please contact the HR department for more specific information on this topic.'
          }
  
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
  }
  
  function setupRealTimeNotifications() {
    // Create notification container if it doesn't exist
    if (!document.querySelector(".notification-container")) {
      const container = document.createElement("div")
      container.className = "notification-container"
      document.body.appendChild(container)
    }
  
    // Demo notification after 3 seconds
    setTimeout(() => {
      showNotification("Welcome", "Welcome to your futuristic employee dashboard!", "info")
    }, 3000)
  
    // Simulate task assignment notification
    setTimeout(() => {
      showNotification("New Task", 'You have been assigned a new task: "Complete quarterly report"', "task")
    }, 10000)
  
    // Simulate leave approval notification
    setTimeout(() => {
      showNotification("Leave Approved", "Your leave request for next week has been approved", "success")
    }, 20000)
  }
  
  function showNotification(title, message, type = "info") {
    const container = document.querySelector(".notification-container")
  
    const notification = document.createElement("div")
    notification.className = `notification ${type}`
  
    notification.innerHTML = `
      <div class="notification-header">
        <div class="notification-title">${title}</div>
        <button class="notification-close">&times;</button>
      </div>
      <div class="notification-body">${message}</div>
      <div class="notification-time">${new Date().toLocaleTimeString()}</div>
    `
  
    container.appendChild(notification)
  
    // Animate in
    gsap.fromTo(notification, { x: 350, opacity: 0 }, { duration: 0.5, x: 0, opacity: 1, ease: "power3.out" })
  
    // Add show class for CSS transitions
    setTimeout(() => {
      notification.classList.add("show")
    }, 10)
  
    // Auto close after 5 seconds
    setTimeout(() => {
      closeNotification(notification)
    }, 5000)
  
    // Close button
    notification.querySelector(".notification-close").addEventListener("click", () => {
      closeNotification(notification)
    })
  }
  
  function closeNotification(notification) {
    // Animate out
    gsap.to(notification, {
      duration: 0.5,
      x: 350,
      opacity: 0,
      ease: "power3.in",
      onComplete: () => {
        notification.remove()
      },
    })
  }
  
  function initializeParallaxEffects() {
    // Add parallax effect to background elements
    document.addEventListener("mousemove", (e) => {
      const x = e.clientX / window.innerWidth
      const y = e.clientY / window.innerHeight
  
      // Apply parallax to elements with .parallax class
      document.querySelectorAll(".parallax").forEach((element) => {
        const speed = element.getAttribute("data-speed") || 0.1
        const moveX = (x - 0.5) * speed * 100
        const moveY = (y - 0.5) * speed * 100
  
        gsap.to(element, {
          duration: 0.5,
          x: moveX,
          y: moveY,
          ease: "power1.out",
        })
      })
    })
  
    // Add parallax effect to cards on scroll
    window.addEventListener("scroll", () => {
      const scrollY = window.scrollY
  
      document.querySelectorAll(".card").forEach((card, index) => {
        const speed = 0.05
        const yPos = -scrollY * speed * ((index % 3) + 1) * 0.1
  
        gsap.to(card, {
          duration: 0.5,
          y: yPos,
          ease: "power1.out",
        })
      })
    })
  }
  
  