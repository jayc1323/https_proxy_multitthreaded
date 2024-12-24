document.addEventListener('DOMContentLoaded', function () {
        const chatbotDiv = document.createElement('div');
        chatbotDiv.id = 'chatbot-container';
        chatbotDiv.style.position = 'fixed';
        chatbotDiv.style.bottom = '10px';
        chatbotDiv.style.right = '10px';
        chatbotDiv.style.width = '300px';
        chatbotDiv.style.height = '400px';
        chatbotDiv.style.border = '1px solid #ccc';
        chatbotDiv.style.background = '#fff';
        chatbotDiv.style.boxShadow = '0 0 10px rgba(0,0,0,0.1)';
        chatbotDiv.style.borderRadius = '8px';
        chatbotDiv.innerHTML = '<p style="padding: 10px;">Chatbot loading...</p>';
        document.body.appendChild(chatbotDiv);
    });
    