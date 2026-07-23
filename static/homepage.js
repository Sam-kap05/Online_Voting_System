  /*____________________SKIP BUTTON____________________*/

  const skipButton = document.getElementById('skip_button');
  const mainContent = document.getElementById('main_content');   // Get the button and the main content section

  if (skipButton && mainContent) {
    skipButton.addEventListener('click', function() {
      mainContent.scrollIntoView({ behavior: 'smooth' });
    })  // adding event listener
  }

  /*____________________TRANSLATE BUTTON____________________*/

  function googleTranslateElementInit() {
    new google.translate.TranslateElement({
      pageLanguage: 'en', // Original language of your page
      includedLanguages:'as,bn,gu,hi,kn,ks,ml,mr,ne,or,pa,sa,sd,ta,te,ur', // Indian languages
      layout: google.translate.TranslateElement.InlineLayout.SIMPLE
    }, 'google_translate_element');
  }

  (function loadGoogleTranslate() {   // Load the Google Translate script dynamically
    const script = document.createElement("script");
    script.type = "text/javascript";
    script.src = "//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit";
    document.body.appendChild(script);
  })();

  /*____________________FONT DROPDOWN____________________*/

  // Get dropdown menu items
  const increaseSize = document.getElementById('increase-size');
  const resetSize = document.getElementById('reset-size');
  const decreaseSize = document.getElementById('decrease-size');

  // Default scale factor
  let scaleFactor = 1;

  // Function to update the scale of specific sections
  function updateScale(scale) {
  document.documentElement.style.setProperty('--scale-factor', scale);
  localStorage.setItem('scaleFactor', scale); // Store user preference
  }

  // Load stored scale settings on page load
  document.addEventListener('DOMContentLoaded', () => {
  const savedScale = localStorage.getItem('scaleFactor');
  if (savedScale) {
    scaleFactor = parseFloat(savedScale);
    updateScale(scaleFactor);
  }
  });

  // Event listeners for size adjustments
  if (increaseSize) {
    increaseSize.addEventListener('click', () => {
      scaleFactor += 0.1; // Increase scale
      updateScale(scaleFactor);
    });
  }

  if (resetSize) {
    resetSize.addEventListener('click', () => {
      scaleFactor = 1; // Reset to default
      updateScale(scaleFactor);
    });
  }

  if (decreaseSize) {
    decreaseSize.addEventListener('click', () => {
      if (scaleFactor > 0.7) { // Prevent from getting too small
        scaleFactor -= 0.1;
        updateScale(scaleFactor);
      }
    });
  }

  //HIGH CONTRAST
  const contrastToggle = document.getElementById('high-contrast'); 
  const mainSection = document.querySelector('.main-section');
  const noteSection = document.querySelector('.note-section');
  const footerLeft = document.querySelector('.footer-left'); // Target the footer-left section

  // Function to toggle high contrast mode for main section, note section, and footer-left
  if (contrastToggle) {
    contrastToggle.addEventListener('click', () => {
      if (mainSection) mainSection.classList.toggle('high-contrast');
      if (noteSection) noteSection.classList.toggle('high-contrast');
      if (footerLeft) footerLeft.classList.toggle('high-contrast'); // Add high-contrast class to footer-left
    });
  }
