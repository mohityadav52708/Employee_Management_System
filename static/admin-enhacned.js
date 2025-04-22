import { Chart } from "@/components/ui/chart"
// Enhanced Admin Dashboard JavaScript
document.addEventListener("DOMContentLoaded", () => {
  // Initialize Chart.js with enhanced animations and styling
  initializeCharts()

  // Setup real-time data updates
  setupRealTimeUpdates()

  // Initialize 3D card effects
  initialize3DEffects()

  // Setup GSAP animations for page elements
  setupGSAPAnimations()
})

function initializeCharts() {
  // Set Chart.js defaults for all charts
  Chart.defaults.font.family = "'Inter', 'Roboto', sans-serif"
  Chart.defaults.color = "rgba(255, 255, 255, 0.7)"
  Chart.defaults.scale.grid.color = "rgba(255, 255, 255, 0.1)"
  Chart.defaults.plugins.tooltip.backgroundColor = "rgba(0, 0, 0, 0.7)"
  Chart.defaults.plugins.tooltip.titleColor = "#00f3ff"
  Chart.defaults.plugins.tooltip.bodyColor = "#ffffff"
  Chart.defaults.plugins.tooltip.borderColor = "#00f3ff"
  Chart.defaults.plugins.tooltip.borderWidth = 1
  Chart.defaults.plugins.tooltip.padding = 10
  Chart.defaults.plugins.tooltip.cornerRadius = 5

  // Task Status Chart
  if (document.getElementById("taskChart")) {
    const taskChartCanvas = document.getElementById("taskChart").getContext("2d")

    // Create gradient
    const taskGradient1 = taskChartCanvas.createLinearGradient(0, 0, 0, 400)
    taskGradient1.addColorStop(0, "rgba(255, 99, 132, 0.8)")
    taskGradient1.addColorStop(1, "rgba(255, 99, 132, 0.2)")

    const taskGradient2 = taskChartCanvas.createLinearGradient(0, 0, 0, 400)
    taskGradient2.addColorStop(0, "rgba(54, 162, 235, 0.8)")
    taskGradient2.addColorStop(1, "rgba(54, 162, 235, 0.2)")

    const taskGradient3 = taskChartCanvas.createLinearGradient(0, 0, 0, 400)
    taskGradient3.addColorStop(0, "rgba(255, 206, 86, 0.8)")
    taskGradient3.addColorStop(1, "rgba(255, 206, 86, 0.2)")

    // Enhanced task chart
    new Chart(taskChartCanvas, {
      type: "bar",
      data: {
        labels: ["Pending", "In Progress", "Completed"],
        datasets: [
          {
            label: "Tasks Status",
            data: [
              document.querySelector("[data-pending]")?.getAttribute("data-pending") || 5,
              document.querySelector("[data-in-progress]")?.getAttribute("data-in-progress") || 8,
              document.querySelector("[data-completed]")?.getAttribute("data-completed") || 12,
            ],
            backgroundColor: [taskGradient1, taskGradient2, taskGradient3],
            borderColor: ["rgba(255, 99, 132, 1)", "rgba(54, 162, 235, 1)", "rgba(255, 206, 86, 1)"],
            borderWidth: 2,
            borderRadius: 5,
            hoverOffset: 10,
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
                size: 12,
              },
              padding: 20,
            },
          },
          title: {
            display: true,
            text: "Task Distribution",
            font: {
              size: 16,
              weight: "bold",
            },
            padding: {
              top: 10,
              bottom: 30,
            },
          },
        },
        animation: {
          duration: 2000,
          easing: "easeOutQuart",
          delay: (context) => context.dataIndex * 300,
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              display: true,
              drawBorder: false,
            },
            ticks: {
              font: {
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
                size: 12,
              },
            },
          },
        },
      },
    })
  }

  // Leave Management Chart
  if (document.getElementById("leaveChart")) {
    const leaveChartCanvas = document.getElementById("leaveChart").getContext("2d")

    new Chart(leaveChartCanvas, {
      type: "doughnut",
      data: {
        labels: ["Pending", "Approved", "Rejected"],
        datasets: [
          {
            data: [
              document.querySelector("[data-leave-pending]")?.getAttribute("data-leave-pending") || 3,
              document.querySelector("[data-leave-approved]")?.getAttribute("data-leave-approved") || 7,
              document.querySelector("[data-leave-rejected]")?.getAttribute("data-leave-rejected") || 2,
            ],
            backgroundColor: ["rgba(255, 206, 86, 0.7)", "rgba(75, 192, 192, 0.7)", "rgba(255, 99, 132, 0.7)"],
            borderColor: ["rgba(255, 206, 86, 1)", "rgba(75, 192, 192, 1)", "rgba(255, 99, 132, 1)"],
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
              padding: 20,
              font: {
                size: 12,
              },
            },
          },
          title: {
            display: true,
            text: "Leave Requests",
            font: {
              size: 16,
              weight: "bold",
            },
            padding: {
              top: 10,
              bottom: 30,
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

  // Employee Attendance Chart
  if (document.getElementById("attendanceChart")) {
    const attendanceChartCanvas = document.getElementById("attendanceChart").getContext("2d")

    const attendanceGradient1 = attendanceChartCanvas.createLinearGradient(0, 0, 0, 400)
    attendanceGradient1.addColorStop(0, "rgba(0, 243, 255, 0.8)")
    attendanceGradient1.addColorStop(1, "rgba(0, 243, 255, 0.2)")

    const attendanceGradient2 = attendanceChartCanvas.createLinearGradient(0, 0, 0, 400)
    attendanceGradient2.addColorStop(0, "rgba(255, 99, 132, 0.8)")
    attendanceGradient2.addColorStop(1, "rgba(255, 99, 132, 0.2)")

    new Chart(attendanceChartCanvas, {
      type: "pie",
      data: {
        labels: ["Online", "Offline"],
        datasets: [
          {
            data: [
              document.querySelector("[data-online]")?.getAttribute("data-online") || 8,
              document.querySelector("[data-offline]")?.getAttribute("data-offline") || 12,
            ],
            backgroundColor: [attendanceGradient1, attendanceGradient2],
            borderColor: ["rgba(0, 243, 255, 1)", "rgba(255, 99, 132, 1)"],
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
              padding: 20,
              font: {
                size: 12,
              },
            },
          },
          title: {
            display: true,
            text: "Employee Attendance",
            font: {
              size: 16,
              weight: "bold",
            },
            padding: {
              top: 10,
              bottom: 30,
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

  // Employee Reviews Chart
  if (document.getElementById("reviewChart")) {
    const reviewChartCanvas = document.getElementById("reviewChart").getContext("2d")

    new Chart(reviewChartCanvas, {
      type: "polarArea",
      data: {
        labels: ["Pending", "Resolved", "Rejected"],
        datasets: [
          {
            data: [
              document.querySelector("[data-review-pending]")?.getAttribute("data-review-pending") || 4,
              document.querySelector("[data-review-resolved]")?.getAttribute("data-review-resolved") || 9,
              document.querySelector("[data-review-rejected]")?.getAttribute("data-review-rejected") || 3,
            ],
            backgroundColor: ["rgba(255, 206, 86, 0.7)", "rgba(153, 102, 255, 0.7)", "rgba(255, 99, 132, 0.7)"],
            borderColor: ["rgba(255, 206, 86, 1)", "rgba(153, 102, 255, 1)", "rgba(255, 99, 132, 1)"],
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
              padding: 20,
              font: {
                size: 12,
              },
            },
          },
          title: {
            display: true,
            text: "Employee Reviews",
            font: {
              size: 16,
              weight: "bold",
            },
            padding: {
              top: 10,
              bottom: 30,
            },
          },
        },
        animation: {
          animateScale: true,
          animateRotate: true,
          duration: 2000,
          easing: "easeOutCirc",
        },
        scales: {
          r: {
            ticks: {
              backdropColor: "transparent",
            },
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
            angleLines: {
              color: "rgba(255, 255, 255, 0.1)",
            },
          },
        },
      },
    })
  }
}

function setupRealTimeUpdates() {
  // In a real implementation, you would connect to your Flask-SocketIO server
  // For demo purposes, we'll simulate real-time updates

  // Simulate new employee coming online
  setInterval(() => {
    // Update online employee count
    const onlineCount = document.getElementById("onlineCount")
    if (onlineCount) {
      const currentCount = Number.parseInt(onlineCount.textContent)
      onlineCount.textContent = currentCount + 1

      // Update chart if it exists
      if (Chart.instances) {
        for (const id in Chart.instances) {
          const chart = Chart.instances[id]
          if (chart.canvas.id === "attendanceChart") {
            chart.data.datasets[0].data[0] += 1
            chart.update()
          }
        }
      }

      // Show notification
      showNotification("Employee Online", "A new employee has logged in", "info")
    }
  }, 60000) // Every minute

  // Simulate new task completion
  setInterval(() => {
    // Update task completion count
    const completedCount = document.getElementById("completedCount")
    if (completedCount) {
      const currentCount = Number.parseInt(completedCount.textContent)
      completedCount.textContent = currentCount + 1

      // Update pending count
      const pendingCount = document.getElementById("pendingCount")
      if (pendingCount) {
        const currentPending = Number.parseInt(pendingCount.textContent)
        if (currentPending > 0) {
          pendingCount.textContent = currentPending - 1
        }
      }

      // Update chart if it exists
      if (Chart.instances) {
        for (const id in Chart.instances) {
          const chart = Chart.instances[id]
          if (chart.canvas.id === "taskChart") {
            chart.data.datasets[0].data[2] += 1 // Completed
            if (chart.data.datasets[0].data[0] > 0) {
              chart.data.datasets[0].data[0] -= 1 // Pending
            }
            chart.update()
          }
        }
      }

      // Show notification
      showNotification("Task Completed", "A task has been marked as completed", "success")
    }
  }, 120000) // Every 2 minutes
}

function initialize3DEffects() {
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
    })

    card.addEventListener("mouseleave", () => {
      card.style.transform = "perspective(1000px) rotateX(0) rotateY(0) scale3d(1, 1, 1)"
    })
  })
}

// Import GSAP and ScrollTrigger
import gsap from "gsap"
import { ScrollTrigger } from "gsap/ScrollTrigger"

function setupGSAPAnimations() {
  // Register ScrollTrigger plugin
  gsap.registerPlugin(ScrollTrigger)

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

  // Card animations
  gsap.from(".card", {
    duration: 0.8,
    y: 50,
    opacity: 0,
    stagger: 0.1,
    ease: "power3.out",
  })

  // Table animation
  gsap.from(".attendance-table", {
    duration: 1,
    y: 50,
    opacity: 0,
    ease: "power3.out",
    delay: 0.5,
  })

  // Chart animations
  gsap.from(".chart-box", {
    duration: 0.8,
    scale: 0.9,
    opacity: 0,
    stagger: 0.2,
    ease: "power3.out",
    delay: 0.8,
  })

  // Scroll animations

  gsap.utils.toArray(".section").forEach((section, i) => {
    ScrollTrigger.create({
      trigger: section,
      start: "top 80%",
      end: "bottom 20%",
      onEnter: () => {
        gsap.to(section, {
          duration: 0.8,
          y: 0,
          opacity: 1,
          ease: "power3.out",
        })
      },
      onLeaveBack: () => {
        gsap.to(section, {
          duration: 0.8,
          y: 50,
          opacity: 0,
          ease: "power3.out",
        })
      },
    })
  })
}

// Function to show notifications
function showNotification(title, message, type = "info") {
  // Create notification element if it doesn't exist
  if (!document.querySelector(".notification-container")) {
    const container = document.createElement("div")
    container.className = "notification-container"
    document.body.appendChild(container)
  }

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

