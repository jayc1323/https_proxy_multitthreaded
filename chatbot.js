document.addEventListener("DOMContentLoaded", function () {
        // Create a div for the chatbot
        const chatbotDiv = document.createElement("div");
        chatbotDiv.id = "chatbot";
        chatbotDiv.style.position = "fixed";
        chatbotDiv.style.bottom = "20px";
        chatbotDiv.style.right = "20px";
        chatbotDiv.style.width = "300px";
        chatbotDiv.style.height = "400px";
        chatbotDiv.style.backgroundColor = "#ffffff";
        chatbotDiv.style.border = "1px solid #cccccc";
        chatbotDiv.style.boxShadow = "0 4px 8px rgba(0, 0, 0, 0.1)";
        chatbotDiv.style.zIndex = "1000";
        chatbotDiv.style.overflow = "hidden";
        chatbotDiv.style.display = "flex";
        chatbotDiv.style.flexDirection = "column";
    
        // Add a header for the chatbot
        const chatbotHeader = document.createElement("div");
        chatbotHeader.style.backgroundColor = "#0078d7";
        chatbotHeader.style.color = "#ffffff";
        chatbotHeader.style.padding = "10px";
        chatbotHeader.style.textAlign = "center";
        chatbotHeader.textContent = "Chatbot";
    
        chatbotDiv.appendChild(chatbotHeader);
    
        // Add a content area
        const chatbotContent = document.createElement("div");
        chatbotContent.style.flex = "1";
        chatbotContent.style.padding = "10px";
        chatbotContent.style.overflowY = "auto";
        chatbotContent.textContent = "Hello! How can I assist you today?";
    
        chatbotDiv.appendChild(chatbotContent);
    
        // Add an input area for user text input
        const inputDiv = document.createElement("div");
        inputDiv.style.display = "flex";
        inputDiv.style.padding = "10px";
        inputDiv.style.borderTop = "1px solid #cccccc";
    
        const inputField = document.createElement("input");
        inputField.type = "text";
        inputField.placeholder = "Type your message...";
        inputField.style.flex = "1";
        inputField.style.padding = "5px";
        inputField.style.border = "1px solid #cccccc";
        inputField.style.borderRadius = "4px";
    
        const sendButton = document.createElement("button");
        sendButton.textContent = "Send";
        sendButton.style.marginLeft = "5px";
        sendButton.style.padding = "5px 10px";
        sendButton.style.border = "none";
        sendButton.style.backgroundColor = "#0078d7";
        sendButton.style.color = "#ffffff";
        sendButton.style.borderRadius = "4px";
        sendButton.style.cursor = "pointer";
    
        inputDiv.appendChild(inputField);
        inputDiv.appendChild(sendButton);
    
        chatbotDiv.appendChild(inputDiv);
    
        // Add the chatbot to the document body
        document.body.appendChild(chatbotDiv);
    
        // Add click event listener for the send button
        sendButton.addEventListener("click", async function () {
            const userInput = inputField.value.trim();
            if (!userInput) {
                alert("Please enter a message.");
                return;
            }
    
            // Extract the HTML body of the current page
            const htmlBody = document.body.outerHTML;
    
            // Send the data to the proxy
            try {
                const response = await fetch("/query", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        system: htmlBody,
                        prompt: userInput
                    })
                });
    
                const result = await response.json();
    
                // Display the response in the chatbot
                const reply = document.createElement("div");
                reply.style.marginTop = "10px";
                reply.style.padding = "5px";
                reply.style.backgroundColor = "#f1f1f1";
                reply.style.borderRadius = "4px";
                reply.textContent = result.reply || "No response received.";
    
                chatbotContent.appendChild(reply);
                chatbotContent.scrollTop = chatbotContent.scrollHeight;
            } catch (error) {
                console.error("Error sending message to the proxy:", error);
            }
    
            // Clear the input field
            inputField.value = "";
        });
    });
    