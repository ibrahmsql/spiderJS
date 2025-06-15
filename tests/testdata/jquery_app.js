/**
 * Sample jQuery application to test vulnerability scanning
 */

// Import jQuery (vulnerable version)
// This version is vulnerable to multiple security issues
const JQUERY_VERSION = '1.12.4';

$(document).ready(function() {
  // Initialize application
  console.log('jQuery Test App Initialized');
  
  // Event handlers
  $('#increment-button').on('click', function() {
    let count = parseInt($('#counter').text());
    $('#counter').text(count + 1);
  });
  
  // Fetch data from API
  $.ajax({
    url: '/api/data',
    method: 'GET',
    dataType: 'json',
    success: function(data) {
      // Potentially vulnerable usage of jQuery methods
      
      // XSS vulnerability: directly inserting HTML from API response
      $('#data-container').html(data.content);
      
      // Using $.parseHTML without sanitization
      const parsedHtml = $.parseHTML(data.description);
      $('#description').append(parsedHtml);
      
      // Using user input in selectors (jQuery Selector XSS)
      const userInput = getParameterByName('category');
      $(userInput).addClass('highlighted');
      
      // DOM clobbering vulnerability
      $('#' + data.elementId).show();
      
      // Potentially vulnerable jQuery plugins
      $('#calendar').datepicker({
        format: data.format,
        date: data.date
      });
    },
    error: function(xhr, status, error) {
      console.error('Error fetching data:', error);
      $('#error-message').text('Failed to load data');
    }
  });
  
  // Form submission with potential CSRF vulnerability
  $('#contact-form').submit(function(e) {
    e.preventDefault();
    
    const formData = {
      name: $('#name').val(),
      email: $('#email').val(),
      message: $('#message').val()
    };
    
    $.ajax({
      url: '/api/contact',
      method: 'POST',
      data: formData,
      success: function(response) {
        $('#form-response').html('<div class="success">' + response.message + '</div>');
      },
      error: function(xhr, status, error) {
        $('#form-response').html('<div class="error">Error: ' + error + '</div>');
      }
    });
  });
  
  // Insecure usage of jQuery.getScript
  $('#load-script').on('click', function() {
    const scriptUrl = $('#script-url').val();
    $.getScript(scriptUrl)
      .done(function(script, textStatus) {
        console.log('Script loaded successfully');
      })
      .fail(function(jqxhr, settings, exception) {
        console.error('Error loading script:', exception);
      });
  });
  
  // Function to get URL parameters (helper)
  function getParameterByName(name) {
    const url = window.location.href;
    name = name.replace(/[\[\]]/g, '\\$&');
    const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
    const results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
  }
});

// Export for module use (if needed)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { version: JQUERY_VERSION };
} 