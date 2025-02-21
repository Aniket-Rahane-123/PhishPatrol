chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
	var tab = tabs[0];
	var url = tab.url;

	const el = document.getElementById("site_score");
const el2 = document.getElementById("site_msg");
fetch('http://localhost:5000/post', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: `URL=${url}`
})
.then(response => response.text())
.then(data => {
  console.log('Server response:', data);
  if (parseInt(data) == 1) { // Suspicious
    alert('Suspicious');
    console.log('1');
    el.textContent = 'Suspicious';
    el2.textContent = 'This website may not be safe';
    el.style.background = "linear-gradient(135deg, #ffae42, #b02a37)"; 
    el.style.transform = "translateZ(5px) scale(1)";

} else if (parseInt(data) == 0) { // Safe
    console.log('0');
    el.textContent = 'Safe';
    el2.textContent = 'This website looks safe to use.';
    el.style.background = "linear-gradient(135deg, #00db2f, #06678b)"; 
    el.style.transform = "translateZ(5px) scale(1)";

} else if (parseInt(data) == -1) { // Phishing
    alert('Phishing');
    console.log('-1');
    el.textContent = 'Phishing';
    el2.textContent = 'This website is not safe to use';
    el.style.background = "linear-gradient(135deg, #ff4d4d, #4d1a00)"; 
    el.style.transform = "translateZ(5px) scale(1)";
}


})
.catch(error => {
  console.error('Fetch error:', error);
});

});