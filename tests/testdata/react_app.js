/**
 * Sample React application to test vulnerability scanning
 */

import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';

// This version is vulnerable to CVE-2021-27119
const REACT_VERSION = '16.13.1';

function App() {
  const [count, setCount] = useState(0);
  const [data, setData] = useState([]);

  useEffect(() => {
    // Fetch data from API
    fetch('/api/data')
      .then(response => response.json())
      .then(data => setData(data))
      .catch(error => console.error('Error fetching data:', error));
  }, []);

  // Potentially vulnerable usage of dangerouslySetInnerHTML
  function createMarkup() {
    return { __html: '<div>User provided content</div>' };
  }

  return (
    <div className="app">
      <h1>React Test App</h1>
      <p>Current count: {count}</p>
      <button onClick={() => setCount(count + 1)}>Increment</button>
      
      {/* Vulnerable pattern - using dangerouslySetInnerHTML */}
      <div dangerouslySetInnerHTML={createMarkup()} />
      
      {/* Potentially vulnerable iframe with srcdoc (CVE-2021-27119) */}
      <iframe 
        srcDoc="<script>console.log('Hello from iframe');</script>" 
        title="Example iframe"
      />
      
      <ul>
        {data.map(item => (
          <li key={item.id}>{item.name}</li>
        ))}
      </ul>
    </div>
  );
}

// Router setup
function MainApp() {
  return (
    <Router>
      <Switch>
        <Route exact path="/" component={App} />
        <Route path="/about" render={() => <h1>About Page</h1>} />
        <Route path="*" render={() => <h1>404 Not Found</h1>} />
      </Switch>
    </Router>
  );
}

// Render app
ReactDOM.render(
  <MainApp />,
  document.getElementById('root')
);

export default App; 