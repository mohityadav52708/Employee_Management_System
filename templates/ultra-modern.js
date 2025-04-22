import { Chart } from "@/components/ui/chart"
/**
 * Ultra-Modern Employee Management System - Main JavaScript
 * This file contains all the core functionality for the EMS
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", () => {
  // Initialize all components
  initDarkMode()
  initSidebar()
  initCharts()
  initCardEffects()
  initNotifications()
  initChatbot()
  initParallaxEffects()
  init3DAnimations()
  initRealTimeUpdates()
})

/**
 * Dark Mode Functionality
 */
function initDarkMode() {
  const darkModeToggle = document.getElementById("darkModeToggle")

  if (!darkModeToggle) return

  // Check for saved preference
  if (localStorage.getItem("darkMode") === "enabled") {
    document.body.classList.add("dark-mode")
  }

  // Toggle dark mode
  darkModeToggle.addEventListener("click", () => {
    document.body.classList.toggle("dark-mode")

    // Save preference
    if (document.body.classList.contains("dark-mode")) {
      localStorage.setItem("darkMode", "enabled")
    } else {
      localStorage.setItem("darkMode", "disabled")
    }
  })
}

/**
 * Sidebar Functionality
 */
function initSidebar() {
  const burgerMenu = document.querySelector(".burger-menu")
  const sidebar = document.querySelector(".sidebar")

  if (!burgerMenu || !sidebar) return

  burgerMenu.addEventListener("click", () => {
    burgerMenu.classList.toggle("active")
    sidebar.classList.toggle("active")
  })

  // Close sidebar when clicking outside on mobile
  document.addEventListener("click", (e) => {
    if (
      window.innerWidth <= 768 &&
      sidebar.classList.contains("active") &&
      !sidebar.contains(e.target) &&
      !burgerMenu.contains(e.target)
    ) {
      sidebar.classList.remove("active")
      burgerMenu.classList.remove("active")
    }
  })

  // Add active class to current page link
  const currentPath = window.location.pathname
  const sidebarLinks = sidebar.querySelectorAll("a")

  sidebarLinks.forEach((link) => {
    const linkPath = new URL(link.href).pathname
    if (currentPath === linkPath) {
      link.classList.add("active")
    }
  })
}

/**
 * Chart Initialization
 */
function initCharts() {
  // Task Chart
  const taskChartEl = document.getElementById("taskChart")
  if (taskChartEl) {
    const ctx = taskChartEl.getContext("2d")

    // Create gradient
    const gradient1 = ctx.createLinearGradient(0, 0, 0, 300)
    gradient1.addColorStop(0, "rgba(99, 102, 241, 0.8)")
    gradient1.addColorStop(1, "rgba(99, 102, 241, 0.2)")

    const gradient2 = ctx.createLinearGradient(0, 0, 0, 300)
    gradient2.addColorStop(0, "rgba(16, 185, 129, 0.8)")
    gradient2.addColorStop(1, "rgba(16, 185, 129, 0.2)")

    const gradient3 = ctx.createLinearGradient(0, 0, 0, 300)
    gradient3.addColorStop(0, "rgba(244, 63, 94, 0.8)")
    gradient3.addColorStop(1, "rgba(244, 63, 94, 0.2)")

    // Get data from data attributes or use defaults
    const pendingTasks = taskChartEl.dataset.pending || 5
    const inProgressTasks = taskChartEl.dataset.inProgress || 8
    const completedTasks = taskChartEl.dataset.completed || 12

    new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Pending", "In Progress", "Completed"],
        datasets: [
          {
            label: "Tasks",
            data: [pendingTasks, inProgressTasks, completedTasks],
            backgroundColor: [gradient1, gradient2, gradient3],
            borderColor: ["rgba(99, 102, 241, 1)", "rgba(16, 185, 129, 1)", "rgba(244, 63, 94, 1)"],
            borderWidth: 2,
            borderRadius: 8,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
              padding: 20,
              usePointStyle: true,
              pointStyle: "circle",
            },
          },
          tooltip: {
            backgroundColor: "rgba(15, 23, 42, 0.8)",
            titleFont: {
              family: "'Inter', sans-serif",
              size: 14,
              weight: "bold",
            },
            bodyFont: {
              family: "'Inter', sans-serif",
              size: 12,
            },
            padding: 12,
            cornerRadius: 8,
            displayColors: false,
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              display: true,
              drawBorder: false,
              color: "rgba(203, 213, 225, 0.2)",
            },
            ticks: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
            },
          },
          x: {
            grid: {
              display: false,
              drawBorder: false,
            },
            ticks: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
            },
          },
        },
        animation: {
          duration: 2000,
          easing: "easeOutQuart",
          delay: (context) => context.dataIndex * 300,
        },
      },
    })
  }

  // Leave Chart
  const leaveChartEl = document.getElementById("leaveChart")
  if (leaveChartEl) {
    const ctx = leaveChartEl.getContext("2d")

    // Get data from data attributes or use defaults
    const pendingLeaves = leaveChartEl.dataset.pending || 3
    const approvedLeaves = leaveChartEl.dataset.approved || 7
    const rejectedLeaves = leaveChartEl.dataset.rejected || 2

    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Pending", "Approved", "Rejected"],
        datasets: [
          {
            data: [pendingLeaves, approvedLeaves, rejectedLeaves],
            backgroundColor: ["rgba(234, 179, 8, 0.7)", "rgba(16, 185, 129, 0.7)", "rgba(244, 63, 94, 0.7)"],
            borderColor: ["rgba(234, 179, 8, 1)", "rgba(16, 185, 129, 1)", "rgba(244, 63, 94, 1)"],
            borderWidth: 2,
            hoverOffset: 15,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
              padding: 20,
              usePointStyle: true,
              pointStyle: "circle",
            },
          },
          tooltip: {
            backgroundColor: "rgba(15, 23, 42, 0.8)",
            titleFont: {
              family: "'Inter', sans-serif",
              size: 14,
              weight: "bold",
            },
            bodyFont: {
              family: "'Inter', sans-serif",
              size: 12,
            },
            padding: 12,
            cornerRadius: 8,
            displayColors: false,
          },
        },
        animation: {
          animateScale: true,
          animateRotate: true,
          duration: 2000,
          easing: "easeOutCirc",
        },
      },
    })
  }

  // Review Chart
  const reviewChartEl = document.getElementById("reviewChart")
  if (reviewChartEl) {
    const ctx = reviewChartEl.getContext("2d")

    // Get data from data attributes or use defaults
    const pendingReviews = reviewChartEl.dataset.pending || 4
    const resolvedReviews = reviewChartEl.dataset.resolved || 9
    const rejectedReviews = reviewChartEl.dataset.rejected || 3

    new Chart(ctx, {
      type: "polarArea",
      data: {
        labels: ["Pending", "Resolved", "Rejected"],
        datasets: [
          {
            data: [pendingReviews, resolvedReviews, rejectedReviews],
            backgroundColor: ["rgba(234, 179, 8, 0.7)", "rgba(99, 102, 241, 0.7)", "rgba(244, 63, 94, 0.7)"],
            borderColor: ["rgba(234, 179, 8, 1)", "rgba(99, 102, 241, 1)", "rgba(244, 63, 94, 1)"],
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
              padding: 20,
              usePointStyle: true,
              pointStyle: "circle",
            },
          },
          tooltip: {
            backgroundColor: "rgba(15, 23, 42, 0.8)",
            titleFont: {
              family: "'Inter', sans-serif",
              size: 14,
              weight: "bold",
            },
            bodyFont: {
              family: "'Inter', sans-serif",
              size: 12,
            },
            padding: 12,
            cornerRadius: 8,
            displayColors: false,
          },
        },
        scales: {
          r: {
            ticks: {
              backdropColor: "transparent",
              font: {
                family: "'Inter', sans-serif",
                size: 10,
              },
            },
            grid: {
              color: "rgba(203, 213, 225, 0.2)",
            },
            angleLines: {
              color: "rgba(203, 213, 225, 0.2)",
            },
            pointLabels: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
            },
          },
        },
        animation: {
          animateScale: true,
          animateRotate: true,
          duration: 2000,
          easing: "easeOutCirc",
        },
      },
    })
  }

  // Attendance Chart
  const attendanceChartEl = document.getElementById("attendanceChart")
  if (attendanceChartEl) {
    const ctx = attendanceChartEl.getContext("2d")

    // Create gradient
    const gradient1 = ctx.createLinearGradient(0, 0, 0, 300)
    gradient1.addColorStop(0, "rgba(16, 185, 129, 0.8)")
    gradient1.addColorStop(1, "rgba(16, 185, 129, 0.2)")

    const gradient2 = ctx.createLinearGradient(0, 0, 0, 300)
    gradient2.addColorStop(0, "rgba(244, 63, 94, 0.8)")
    gradient2.addColorStop(1, "rgba(244, 63, 94, 0.2)")

    // Get data from data attributes or use defaults
    const onlineCount = attendanceChartEl.dataset.online || 8
    const offlineCount = attendanceChartEl.dataset.offline || 12

    new Chart(ctx, {
      type: "pie",
      data: {
        labels: ["Online", "Offline"],
        datasets: [
          {
            data: [onlineCount, offlineCount],
            backgroundColor: [gradient1, gradient2],
            borderColor: ["rgba(16, 185, 129, 1)", "rgba(244, 63, 94, 1)"],
            borderWidth: 2,
            hoverOffset: 15,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              font: {
                family: "'Inter', sans-serif",
                size: 12,
              },
              padding: 20,
              usePointStyle: true,
              pointStyle: "circle",
            },
          },
          tooltip: {
            backgroundColor: "rgba(15, 23, 42, 0.8)",
            titleFont: {
              family: "'Inter', sans-serif",
              size: 14,
              weight: "bold",
            },
            bodyFont: {
              family: "'Inter', sans-serif",
              size: 12,
            },
            padding: 12,
            cornerRadius: 8,
            displayColors: false,
          },
        },
        animation: {
          animateScale: true,
          animateRotate: true,
          duration: 2000,
          easing: "easeOutCirc",
        },
      },
    })
  }
}

/**
 * 3D Card Effects
 */
function initCardEffects() {
  // 3D Tilt Effect for Cards
  const cards = document.querySelectorAll(".glass-card, .dashboard-card")

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
        ${deltaX * -1}px ${deltaY * -1}px 20px rgba(99, 102, 241, 0.2),
        0 10px 20px rgba(0, 0, 0, 0.1)
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
      card.style.boxShadow = ""

      const shine = card.querySelector(".shine")
      if (shine) {
        shine.style.backgroundPosition = "50% 50%"
      }
    })
  })

  // 3D Card Flip Effect
  const flipCards = document.querySelectorAll(".card-3d")

  flipCards.forEach((card) => {
    card.addEventListener("click", () => {
      card.classList.toggle("flipped")

      const inner = card.querySelector(".card-3d-inner")
      if (inner) {
        if (card.classList.contains("flipped")) {
          inner.style.transform = "rotateY(180deg)"
        } else {
          inner.style.transform = "rotateY(0)"
        }
      }
    })
  })
}

/**
 * Notification System
 */
function initNotifications() {
  // Create notification container if it doesn't exist
  if (!document.querySelector(".notification-container")) {
    const container = document.createElement("div")
    container.className = "notification-container"
    container.style.position = "fixed"
    container.style.bottom = "20px"
    container.style.right = "20px"
    container.style.zIndex = "1000"
    container.style.display = "flex"
    container.style.flexDirection = "column"
    container.style.gap = "10px"
    document.body.appendChild(container)
  }

  // Show welcome notification after 2 seconds
  setTimeout(() => {
    showNotification("Welcome", "Welcome to the Ultra-Modern Employee Management System!", "info")
  }, 2000)
}

/**
 * Show a notification
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, info)
 */
function showNotification(title, message, type = "info") {
  const container = document.querySelector(".notification-container")

  const notification = document.createElement("div")
  notification.className = `notification notification-${type}`

  // Icon based on type
  let icon = ""
  switch (type) {
    case "success":
      icon =
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>'
      break
    case "error":
      icon =
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>'
      break
    default:
      icon =
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>'
  }

  notification.innerHTML = `
    <div class="notification-icon">${icon}</div>
    <div class="notification-content">
      <div class="notification-title">${title}</div>
      <div class="notification-message">${message}</div>
    </div>
    <button class="notification-close">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="18" y1="6" x2="6" y2="18"></line>
        <line x1="6" y1="6" x2="18" y2="18"></line>
      </svg>
    </button>
  `

  container.appendChild(notification)

  // Animate in
  setTimeout(() => {
    notification.style.transform = "translateX(0)"
    notification.style.opacity = "1"
  }, 10)

  // Auto close after 5 seconds
  const timeout = setTimeout(() => {
    closeNotification(notification)
  }, 5000)

  // Close button
  const closeBtn = notification.querySelector(".notification-close")
  closeBtn.addEventListener("click", () => {
    clearTimeout(timeout)
    closeNotification(notification)
  })
}

/**
 * Close a notification
 * @param {HTMLElement} notification - The notification element to close
 */
function closeNotification(notification) {
  notification.style.transform = "translateX(100%)"
  notification.style.opacity = "0"

  // Remove from DOM after animation
  setTimeout(() => {
    notification.remove()
  }, 300)
}

/**
 * Chatbot Functionality
 */
function initChatbot() {
  // Create chatbot toggle button if it doesn't exist
  if (!document.querySelector(".chatbot-toggle")) {
    const chatbotToggle = document.createElement("button")
    chatbotToggle.className = "chatbot-toggle"
    chatbotToggle.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>'
    document.body.appendChild(chatbotToggle)
  }

  // Create chatbot container if it doesn't exist
  if (!document.querySelector(".chatbot-container")) {
    const chatbotContainer = document.createElement("div")
    chatbotContainer.className = "chatbot-container"
    chatbotContainer.innerHTML = `
      <div class="chatbot-header">
        <h3>HR Assistant</h3>
        <button class="chatbot-close">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      </div>
      <div class="chatbot-messages">
        <div class="chat-message bot">
          Hello! I'm your HR assistant. How can I help you today?
        </div>
      </div>
      <div class="chatbot-input">
        <input type="text" placeholder="Type your message..." />
        <button>
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"></line>
            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
          </svg>
        </button>
      </div>
    `
    document.body.appendChild(chatbotContainer)
  }

  const chatbotToggle = document.querySelector(".chatbot-toggle")
  const chatbotContainer = document.querySelector(".chatbot-container")
  const chatbotClose = document.querySelector(".chatbot-close")
  const chatbotInput = document.querySelector(".chatbot-input input")
  const chatbotSend = document.querySelector(".chatbot-input button")
  const chatbotMessages = document.querySelector(".chatbot-messages")

  // Toggle chatbot
  chatbotToggle.addEventListener("click", () => {
    chatbotContainer.classList.toggle("active")

    if (chatbotContainer.classList.contains("active")) {
      chatbotInput.focus()
    }
  })

  // Close chatbot
  chatbotClose.addEventListener("click", () => {
    chatbotContainer.classList.remove("active")
  })

  // Send message
  function sendMessage() {
    const message = chatbotInput.value.trim()

    if (message) {
      // Add user message
      const userMessage = document.createElement("div")
      userMessage.className = "chat-message user"
      userMessage.textContent = message
      chatbotMessages.appendChild(userMessage)

      // Clear input
      chatbotInput.value = ""

      // Scroll to bottom
      chatbotMessages.scrollTop = chatbotMessages.scrollHeight

      // Add typing indicator
      const typingIndicator = document.createElement("div")
      typingIndicator.className = "chat-message bot typing"
      typingIndicator.innerHTML = "<span>.</span><span>.</span><span>.</span>"
      chatbotMessages.appendChild(typingIndicator)

      // Scroll to bottom
      chatbotMessages.scrollTop = chatbotMessages.scrollHeight

      // Simulate bot response
      setTimeout(() => {
        // Remove typing indicator
        typingIndicator.remove()

        // Add bot response
        const botMessage = document.createElement("div")
        botMessage.className = "chat-message bot"

        // Simple responses based on keywords
        if (message.toLowerCase().includes("leave") || message.toLowerCase().includes("vacation")) {
          botMessage.textContent =
            "You currently have 15 days of annual leave remaining. To apply for leave, go to the Leave Management section and fill out the request form."
        } else if (message.toLowerCase().includes("salary") || message.toLowerCase().includes("pay")) {
          botMessage.textContent =
            "Your next salary payment is scheduled for the 30th of this month. For detailed salary information, please check the Payroll section."
        } else if (message.toLowerCase().includes("hello") || message.toLowerCase().includes("hi")) {
          botMessage.textContent = "Hello! How can I assist you with HR-related queries today?"
        } else {
          botMessage.textContent = `I understand you're asking about "${message}". Please contact the HR department for more specific information on this topic.`
        }

        chatbotMessages.appendChild(botMessage)

        // Scroll to bottom
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight
      }, 1500)
    }
  }

  chatbotSend.addEventListener("click", sendMessage)

  chatbotInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      sendMessage()
    }
  })
}

/**
 * Parallax Effects
 */
function initParallaxEffects() {
  const parallaxContainers = document.querySelectorAll(".parallax-container")

  parallaxContainers.forEach((container) => {
    const layers = container.querySelectorAll(".parallax-layer")

    container.addEventListener("mousemove", (e) => {
      const rect = container.getBoundingClientRect()
      const x = (e.clientX - rect.left) / rect.width
      const y = (e.clientY - rect.top) / rect.height

      layers.forEach((layer, index) => {
        const depth = index / layers.length
        const moveX = (x - 0.5) * depth * 50
        const moveY = (y - 0.5) * depth * 50

        layer.style.transform = `translate3d(${moveX}px, ${moveY}px, 0)`
      })
    })

    container.addEventListener("mouseleave", () => {
      layers.forEach((layer) => {
        layer.style.transform = "translate3d(0, 0, 0)"
      })
    })
  })

  // Parallax scroll effect
  window.addEventListener("scroll", () => {
    const scrollY = window.scrollY

    document.querySelectorAll(".parallax-scroll").forEach((element) => {
      const speed = element.dataset.speed || 0.1
      element.style.transform = `translateY(${scrollY * speed}px)`
    })
  })
}

/**
 * 3D Animations
 */
function init3DAnimations() {
  // Float animation
  document.querySelectorAll(".float-3d").forEach((element) => {
    setInterval(() => {
      element.style.transform = `translateY(${Math.sin(Date.now() / 1000) * 10}px)`
    }, 100)
  })

  // Pulse animation
  document.querySelectorAll(".pulse-3d").forEach((element) => {
    setInterval(() => {
      const scale = 1 + Math.sin(Date.now() / 1000) * 0.05
      element.style.transform = `scale(${scale})`
    }, 100)
  })

  // Rotate animation
  document.querySelectorAll(".rotate-3d").forEach((element) => {
    setInterval(() => {
      const rotateX = Math.sin(Date.now() / 2000) * 10
      const rotateY = Math.cos(Date.now() / 2000) * 10
      element.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`
    }, 100)
  })
}

/**
 * Real-time Updates
 */
function initRealTimeUpdates() {
  // Simulate real-time updates
  setInterval(() => {
    // Update online employee count
    const onlineCountEl = document.getElementById("onlineCount")
    if (onlineCountEl) {
      const currentCount = Number.parseInt(onlineCountEl.textContent)
      const newCount = Math.random() > 0.5 ? currentCount + 1 : Math.max(1, currentCount - 1)
      onlineCountEl.textContent = newCount

      // Update attendance chart
      const attendanceChart = Chart.getChart(document.getElementById("attendanceChart"))
      if (attendanceChart) {
        attendanceChart.data.datasets[0].data[0] = newCount
        attendanceChart.data.datasets[0].data[1] = 20 - newCount // Assuming total employees is 20
        attendanceChart.update()
      }

      // Show notification for new login/logout
      if (newCount > currentCount) {
        showNotification("Employee Online", "A new employee has logged in", "info")
      } else if (newCount < currentCount) {
        showNotification("Employee Offline", "An employee has logged out", "info")
      }
    }

    // Update task completion
    const taskCompletedEl = document.getElementById("taskCompleted")
    if (taskCompletedEl && Math.random() > 0.7) {
      const currentCompleted = Number.parseInt(taskCompletedEl.textContent)
      taskCompletedEl.textContent = currentCompleted + 1

      // Update task chart
      const taskChart = Chart.getChart(document.getElementById("taskChart"))
      if (taskChart) {
        taskChart.data.datasets[0].data[2] += 1 // Completed
        taskChart.data.datasets[0].data[0] = Math.max(0, taskChart.data.datasets[0].data[0] - 1) // Pending
        taskChart.update()
      }

      showNotification("Task Completed", "A task has been marked as completed", "success")
    }
  }, 30000) // Every 30 seconds
}

/**
 * Initialize on page load
 */
window.addEventListener("load", () => {
  // Fade in elements
  document.querySelectorAll(".fade-in").forEach((element, index) => {
    setTimeout(() => {
      element.style.opacity = "1"
    }, 100 * index)
  })

  // Slide in elements
  document.querySelectorAll(".slide-in-left").forEach((element, index) => {
    setTimeout(() => {
      element.style.transform = "translateX(0)"
      element.style.opacity = "1"
    }, 100 * index)
  })

  document.querySelectorAll(".slide-in-right").forEach((element, index) => {
    setTimeout(() => {
      element.style.transform = "translateX(0)"
      element.style.opacity = "1"
    }, 100 * index)
  })

  document.querySelectorAll(".slide-in-up").forEach((element, index) => {
    setTimeout(() => {
      element.style.transform = "translateY(0)"
      element.style.opacity = "1"
    }, 100 * index)
  })
})

/**
 * Utility Functions
 */

// Format date
function formatDate(date) {
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  })
}

// Format time
function formatTime(date) {
  return new Date(date).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  })
}

// Format number
function formatNumber(number) {
  return number.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",")
}

// Format currency
function formatCurrency(number) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(number)
}

// Generate random ID
function generateId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
}

// Debounce function
function debounce(func, wait) {
  let timeout
  return function (...args) {
    clearTimeout(timeout)
    timeout = setTimeout(() => func.apply(this, args), wait)
  }
}

// Throttle function
function throttle(func, limit) {
  let inThrottle
  return function (...args) {
    if (!inThrottle) {
      func.apply(this, args)
      inThrottle = true
      setTimeout(() => (inThrottle = false), limit)
    }
  }
}

