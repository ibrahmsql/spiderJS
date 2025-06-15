/**
 * Sample Vue.js application to test vulnerability scanning
 */

import Vue from 'vue';
import Router from 'vue-router';
import Vuex from 'vuex';

// This version is vulnerable to CVE-2023-49082
const VUE_VERSION = '3.3.9';

Vue.use(Router);
Vue.use(Vuex);

// Create store
const store = new Vuex.Store({
  state: {
    count: 0,
    items: []
  },
  mutations: {
    increment(state) {
      state.count++;
    },
    setItems(state, items) {
      state.items = items;
    }
  },
  actions: {
    fetchItems({ commit }) {
      fetch('/api/items')
        .then(response => response.json())
        .then(data => commit('setItems', data))
        .catch(error => console.error('Error fetching items:', error));
    }
  }
});

// Create component with v-html (potential vulnerability in CVE-2022-23577)
const App = {
  template: `
    <div class="app">
      <h1>Vue Test App</h1>
      <p>Count: {{ count }}</p>
      <button @click="increment">Increment</button>
      
      <!-- Vulnerable v-html usage (CVE-2022-23577) -->
      <div v-html="userContent"></div>
      
      <!-- Vulnerable v-bind:style (CVE-2023-49082) -->
      <div v-bind:style="userStyles"></div>
      
      <ul>
        <li v-for="item in items" :key="item.id">{{ item.name }}</li>
      </ul>
    </div>
  `,
  computed: {
    count() {
      return this.$store.state.count;
    },
    items() {
      return this.$store.state.items;
    }
  },
  data() {
    return {
      userContent: '<div>User provided content</div>',
      userStyles: {
        color: 'red',
        background: 'url("data:image/svg+xml,...")'
      }
    };
  },
  methods: {
    increment() {
      this.$store.commit('increment');
    }
  },
  created() {
    this.$store.dispatch('fetchItems');
  }
};

// Create router
const router = new Router({
  mode: 'history',
  routes: [
    { path: '/', component: App },
    { path: '*', redirect: '/' }
  ]
});

// Create and mount Vue instance
new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app');

export default App; 