package framework

import (
	"context"
	"testing"

	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDetector(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Test with valid logger
	detector, err := NewDetector(log)
	assert.NoError(t, err)
	assert.NotNil(t, detector)

	// Test with nil logger
	detector, err = NewDetector(nil)
	assert.Error(t, err)
	assert.Nil(t, detector)
}

func TestDetect(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test with nil target
	frameworks, err := detector.Detect(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frameworks, err = detector.Detect(ctx, &models.Target{})
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with empty target
	target, err := models.NewTarget("https://example.com")
	require.NoError(t, err)
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.Empty(t, frameworks)

	// Test with React script
	target.Scripts = append(target.Scripts, `
		import React from 'react';
		import ReactDOM from 'react-dom';
		
		function App() {
			const [count, setCount] = React.useState(0);
			
			React.useEffect(() => {
				document.title = 'Count: ' + count;
			}, [count]);
			
			return React.createElement('div', null, 'Hello React!');
		}
		
		ReactDOM.render(
			React.createElement(App, null),
			document.getElementById('root')
		);
	`)
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == React {
			assert.Equal(t, React, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}

	// Test with Vue script
	target.Scripts = []string{`
		import Vue from 'vue';
		
		new Vue({
			el: '#app',
			data: {
				message: 'Hello Vue!'
			},
			computed: {
				reversedMessage() {
					return this.message.split('').reverse().join('');
				}
			},
			watch: {
				message(newVal, oldVal) {
					console.log('Message changed from', oldVal, 'to', newVal);
				}
			}
		});
	`}
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == Vue {
			assert.Equal(t, Vue, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}

	// Test with Angular script
	target.Scripts = []string{`
		import { Component } from '@angular/core';
		
		@Component({
			selector: 'app-root',
			template: '<h1>Hello Angular!</h1>'
		})
		export class AppComponent {
			title = 'My Angular App';
		}
		
		import { NgModule } from '@angular/core';
		import { BrowserModule } from '@angular/platform-browser';
		
		@NgModule({
			declarations: [AppComponent],
			imports: [BrowserModule],
			bootstrap: [AppComponent]
		})
		export class AppModule { }
	`}
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == Angular {
			assert.Equal(t, Angular, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}
}

func TestDetectFromTarget(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test with nil target
	frameworks, err := detector.DetectFromTarget(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frameworks, err = detector.DetectFromTarget(ctx, &models.Target{})
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with empty target
	target, err := models.NewTarget("https://example.com")
	require.NoError(t, err)
	frameworks, err = detector.DetectFromTarget(context.Background(), target)
	assert.NoError(t, err)
	assert.Empty(t, frameworks)

	// Test with headers
	target.Headers["X-Powered-By"] = "Next.js"
	frameworks, err = detector.DetectFromTarget(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == NextJS {
			assert.Equal(t, NextJS, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}
}

func TestDetectVersion(t *testing.T) {
	log := logger.NewMockLogger()
	detector, err := NewDetector(log)
	assert.NoError(t, err)
	assert.NotNil(t, detector)

	tests := []struct {
		name      string
		framework FrameworkType
		target    *models.Target
		expected  string
	}{
		{
			name:      "React version from script URL",
			framework: React,
			target: &models.Target{
				Scripts: []string{"https://unpkg.com/react@17.0.2/umd/react.production.min.js"},
			},
			expected: "17.0.2",
		},
		{
			name:      "Vue version from script URL",
			framework: Vue,
			target: &models.Target{
				Scripts: []string{"https://unpkg.com/vue@3.2.31/dist/vue.esm-browser.js"},
			},
			expected: "3.2.31",
		},
		{
			name:      "Vue 2.x detection",
			framework: Vue,
			target: &models.Target{
				Scripts: []string{"new Vue({el: '#app', data: {message: 'Hello Vue!'}})"},
			},
			expected: "2.x",
		},
		{
			name:      "Vue 3.x detection",
			framework: Vue,
			target: &models.Target{
				Scripts: []string{"Vue.createApp({data() {return {message: 'Hello Vue!'}}}).mount('#app')"},
			},
			expected: "3.x",
		},
		{
			name:      "Angular version from script URL",
			framework: Angular,
			target: &models.Target{
				Scripts: []string{"https://unpkg.com/angular@1.8.2/angular.min.js"},
			},
			expected: "1.8.2",
		},
		{
			name:      "AngularJS detection",
			framework: Angular,
			target: &models.Target{
				Scripts: []string{"https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"},
			},
			expected: "1.8.2",
		},
		{
			name:      "Angular 2+ detection",
			framework: Angular,
			target: &models.Target{
				Scripts: []string{"https://example.com/node_modules/@angular/core/bundles/core.umd.js"},
			},
			expected: "2+",
		},
		{
			name:      "Next.js version from header",
			framework: NextJS,
			target: &models.Target{
				Headers: map[string]string{
					"X-Powered-By": "Next.js 12.1.0",
				},
			},
			expected: "12.1.0",
		},
		{
			name:      "Nuxt.js version from header",
			framework: NuxtJS,
			target: &models.Target{
				Headers: map[string]string{
					"Server": "Nuxt 3.0.0",
				},
			},
			expected: "3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := detector.detectVersion(tt.framework, tt.target)
			assert.Equal(t, tt.expected, version)
		})
	}
}

func TestIsMetaFramework(t *testing.T) {
	log := logger.NewMockLogger()
	detector, err := NewDetector(log)
	assert.NoError(t, err)
	assert.NotNil(t, detector)

	tests := []struct {
		name      string
		framework FrameworkType
		expected  bool
	}{
		{
			name:      "React is not meta-framework",
			framework: React,
			expected:  false,
		},
		{
			name:      "Vue is not meta-framework",
			framework: Vue,
			expected:  false,
		},
		{
			name:      "Next.js is meta-framework",
			framework: NextJS,
			expected:  true,
		},
		{
			name:      "Nuxt.js is meta-framework",
			framework: NuxtJS,
			expected:  true,
		},
		{
			name:      "Gatsby is meta-framework",
			framework: Gatsby,
			expected:  true,
		},
		{
			name:      "Remix is meta-framework",
			framework: Remix,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isMeta := detector.isMetaFramework(tt.framework)
			assert.Equal(t, tt.expected, isMeta)
		})
	}
}

func TestDetectError(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test with nil target
	frameworks, err := detector.Detect(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with empty target
	target := &models.Target{}
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.Empty(t, frameworks)
}
