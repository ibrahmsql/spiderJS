/**
 * Sample Angular application to test vulnerability scanning
 */

import { Component, NgModule, OnInit } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

// This version is vulnerable to multiple CVEs
const ANGULAR_VERSION = '1.7.2';

@Component({
  selector: 'app-root',
  template: `
    <div class="app-container">
      <h1>{{ title }}</h1>
      <p>Count: {{ count }}</p>
      <button (click)="increment()">Increment</button>
      
      <!-- Potentially vulnerable ng-srcset attribute (CVE-2024-21490) -->
      <img ng-srcset="{{ imageUrl }} 1x, {{ imageUrl }} 2x">
      
      <!-- Vulnerable ng-include with user input -->
      <div ng-include="userProvidedTemplate"></div>
      
      <!-- Vulnerable input[type=url] with user input (CVE-2023-26118) -->
      <input type="url" ng-model="userUrl" name="userUrl">
      
      <ul>
        <li *ngFor="let item of items">{{ item.name }}</li>
      </ul>
    </div>
  `
})
export class AppComponent /* implements OnInit */ {
  title = 'Angular Test App';
  count = 0;
  items = [];
  imageUrl = 'assets/image.jpg';
  userProvidedTemplate = 'template.html';
  userUrl = 'https://example.com';
  
  increment() {
    this.count++;
    
    // Vulnerable angular.copy() usage (CVE-2023-26116)
    const newItems = angular.copy(this.items);
    
    // Using textarea interpolation (CVE-2022-25869)
    const template = `
      <textarea>{{ userInput }}</textarea>
    `;
  }
  
  ngOnInit() {
    // Fetch data
    fetch('/api/data')
      .then(response => response.json())
      .then(data => this.items = data)
      .catch(error => console.error('Error fetching data:', error));
  }
}

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    FormsModule,
    RouterModule.forRoot([
      { path: '', component: AppComponent },
      { path: '**', redirectTo: '' }
    ])
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }

// Bootstrap the application
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';

platformBrowserDynamic().bootstrapModule(AppModule)
  .catch(err => console.error(err));

export default AppComponent; 