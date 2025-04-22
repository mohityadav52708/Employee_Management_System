import { Chart } from "@/components/ui/chart"
// Initialize GSAP
document.addEventListener("DOMContentLoaded", () => {
  // Register GSAP plugins if needed
  gsap.registerPlugin(ScrollTrigger)

  // Page load animation
  const timeline = gsap.timeline()

  timeline.from(".sidebar", {
    duration: 1,
    x: -100,
    opacity: 0,
    ease: "power3.out",
  })

  timeline.from(
    ".image",
    {
      duration: 0.8,
      y: -50,
      opacity: 0,
      ease: "power3.out",
    },
    "-=0.5",
  )

  timeline.from(
    ".card",
    {
      duration: 0.8,
      y: 50,
      opacity: 0,
      stagger: 0.1,
      ease: "power3.out",
    },
    "-=0.3",
  )

  // Sidebar link hover effect
  const sidebarLinks = document.querySelectorAll(".sidebar a")

  sidebarLinks.forEach((link) => {
    link.addEventListener("mouseenter", () => {
      gsap.to(link, {
        duration: 0.3,
        color: "#00f3ff",
        paddingLeft: "25px",
        ease: "power2.out",
      })
    })

    link.addEventListener("mouseleave", () => {
      gsap.to(link, {
        duration: 0.3,
        color: "#ffffff",
        paddingLeft: "12px",
        ease: "power2.out",
      })
    })
  })

  // Card hover effects
  const cards = document.querySelectorAll(".card")

  cards.forEach((card) => {
    card.addEventListener("mouseenter", () => {
      gsap.to(card, {
        duration: 0.3,
        y: -10,
        boxShadow: "0 15px 30px rgba(0, 0, 0, 0.3)",
        ease: "power2.out",
      })
    })

    card.addEventListener("mouseleave", () => {
      gsap.to(card, {
        duration: 0.3,
        y: 0,
        boxShadow: "0 5px 15px rgba(0, 0, 0, 0.1)",
        ease: "power2.out",
      })
    })
  })

  // 3D Parallax effect
  const parallaxContainer = document.querySelector(".parallax-container")

  if (parallaxContainer) {
    const layers = document.querySelectorAll(".parallax-layer")

    parallaxContainer.addEventListener("mousemove", (e) => {
      const x = e.clientX / window.innerWidth
      const y = e.clientY / window.innerHeight

      layers.forEach((layer, index) => {
        const depth = index / layers.length
        const moveX = (x - 0.5) * depth * 50
        const moveY = (y - 0.5) * depth * 50

        gsap.to(layer, {
          duration: 0.5,
          x: moveX,
          y: moveY,
          ease: "power2.out",
        })
      })
    })

    parallaxContainer.addEventListener("mouseleave", () => {
      layers.forEach((layer) => {
        gsap.to(layer, {
          duration: 0.5,
          x: 0,
          y: 0,
          ease: "power2.out",
        })
      })
    })
  }

  // Dark mode toggle
  const darkModeToggle = document.getElementById("darkModeToggle")

  if (darkModeToggle) {
    darkModeToggle.addEventListener("click", () => {
      document.body.classList.toggle("dark-mode")

      // Save preference to localStorage
      if (document.body.classList.contains("dark-mode")) {
        localStorage.setItem("darkMode", "enabled")
      } else {
        localStorage.setItem("darkMode", "disabled")
      }
    })

    // Check for saved preference
    if (localStorage.getItem("darkMode") === "enabled") {
      document.body.classList.add("dark-mode")
    }
  }

  // Initialize notifications system
  initNotifications()

  // Initialize chatbot
  initChatbot()

  // Initialize real-time updates
  initRealTimeUpdates()
})

// Notification System
function initNotifications() {
  // Create notification container if it doesn't exist
  if (!document.querySelector(".notification-container")) {
    const container = document.createElement("div")
    container.className = "notification-container"
    document.body.appendChild(container)
  }

  // Demo notification after 3 seconds
  setTimeout(() => {
    showNotification("System Update", "Welcome to the new futuristic interface!", "info")
  }, 3000)
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
  notification.classList.remove("show")

  // Remove from DOM after animation
  setTimeout(() => {
    notification.remove()
  }, 500)
}

// Chatbot System
function initChatbot() {
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

      // Clear input
      input.value = ""

      // Scroll to bottom
      messagesContainer.scrollTop = messagesContainer.scrollHeight

      // Simulate bot response
      setTimeout(() => {
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

        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight
      }, 1000)
    }
  }

  sendBtn.addEventListener("click", sendMessage)

  input.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      sendMessage()
    }
  })
}

// Real-time Updates System
function initRealTimeUpdates() {
  // Simulate real-time updates with WebSocket
  // In a real implementation, you would connect to your Flask-SocketIO server

  // Simulate new employee coming online
  setTimeout(() => {
    const onlineEmployees = document.querySelector(".online-employees")

    if (onlineEmployees) {
      const newEmployee = document.createElement("div")
      newEmployee.className = "online-employee"
      newEmployee.textContent = "john.doe@example.com - Just now"
      newEmployee.style.opacity = "0"

      onlineEmployees.appendChild(newEmployee)

      // Animate in
      gsap.to(newEmployee, {
        duration: 0.5,
        opacity: 1,
        y: 0,
        ease: "power2.out",
      })

      // Show notification
      showNotification("Employee Online", "John Doe has just logged in", "info")

      // Update charts if they exist
      updateCharts()
    }
  }, 10000)
}

// Update Charts
function updateCharts() {
  // Find all chart instances
  const charts = Chart.instances

  // Loop through charts and update with new data
  for (const id in charts) {
    const chart = charts[id]

    // Example: Update attendance chart with new data
    if (chart.canvas.id === "attendanceChart") {
      // Increment online count
      chart.data.datasets[0].data[0] += 1
      chart.update()
    }
  }
}

// 3D Parallax Scrolling
window.addEventListener("scroll", () => {
  const scrollY = window.scrollY

  // Apply parallax effect to elements with .parallax class
  document.querySelectorAll(".parallax").forEach((element, index) => {
    const speed = element.getAttribute("data-speed") || 0.1
    element.style.transform = `translateY(${scrollY * speed}px)`
  })
})

// Initialize custom cursor
function initCustomCursor() {
  const cursor = document.createElement("div")
  cursor.className = "custom-cursor"
  document.body.appendChild(cursor)

  const cursorDot = document.createElement("div")
  cursorDot.className = "cursor-dot"
  document.body.appendChild(cursorDot)

  document.addEventListener("mousemove", (e) => {
    gsap.to(cursor, {
      duration: 0.5,
      x: e.clientX,
      y: e.clientY,
      ease: "power2.out",
    })

    gsap.to(cursorDot, {
      duration: 0.1,
      x: e.clientX,
      y: e.clientY,
    })
  })

  // Scale effect on clickable elements
  document.querySelectorAll("a, button, .card, .btn").forEach((element) => {
    element.addEventListener("mouseenter", () => {
      gsap.to(cursor, {
        duration: 0.3,
        scale: 1.5,
        backgroundColor: "rgba(0, 243, 255, 0.2)",
        ease: "power2.out",
      })
    })

    element.addEventListener("mouseleave", () => {
      gsap.to(cursor, {
        duration: 0.3,
        scale: 1,
        backgroundColor: "rgba(255, 255, 255, 0.1)",
        ease: "power2.out",
      })
    })
  })
}

