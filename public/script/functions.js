// public/js/functions.js

// Function to handle checkbox selection and show/hide delete button
function handleCheckboxSelection() {
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    const deleteButton = document.getElementById('deleteButton');
    
    // Hide the delete button initially
    deleteButton.style.display = 'none';

    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            const checkedCheckboxes = document.querySelectorAll('input[type="checkbox"]:checked');
            if (checkedCheckboxes.length > 0) {
                deleteButton.style.display = 'block';
            } else {
                deleteButton.style.display = 'none';
            }
        });
    });
}


document.addEventListener("DOMContentLoaded", function () {
    handleCheckboxSelection();
    const deleteButton = document.getElementById("deleteButton");
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    const packetTableBody = document.getElementById("packet-table-body");

    deleteButton.addEventListener("click", async () => {
      const selectedPackets = [];
      checkboxes.forEach((checkbox) => {
        if (checkbox.checked) {
          const packetId = checkbox.dataset.packetId;
          // Now you can use the packetId variable as needed
          selectedPackets.push(packetId);
        }
      });

      // Send a request to delete the selected packets
      const response = await fetch("/user/deletePackets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ packetIds: selectedPackets }),
      });

      if (response.ok) {
        // Remove the selected rows from the table
        selectedPackets.forEach((packetId) => {
          const row = document.querySelector(
            `tr[data-packet-id="${packetId}"]`
          );
          if (row) {
            packetTableBody.removeChild(row);
          }
        });
      } else {
        // Handle error
        console.error("Failed to delete packets");
      }
    });
  });

document.addEventListener("DOMContentLoaded", function () {
    // Check if the URL contains the signup parameter
    const urlParams = new URLSearchParams(window.location.search);
    const signupParam = urlParams.get("signup");

    // If the signup parameter is present, automatically check the checkbox
    if (signupParam === "true") {
      setTimeout(() => {
        const checkbox = document.getElementById("reg-log");
        if (checkbox) {
          checkbox.checked = true;
        }
      }, 500);
    }
  });