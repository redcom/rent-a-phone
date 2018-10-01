export default {
  Query: {
    device: (parent, params = {}, context = {}) => { console.log(parent, params, context); return { id: 1, name: '2222' } },
  },
}
