contract {
  participants: [owner]
  scopeSpec: "com.figure.helloWorld"
  fun {
    name: "name"
    inputs: [{
      name: "name"
      type: "ExampleName"
    }]
    outputs: [{
      type: "ExampleName"
    }]
    body: {
      lang: kotlin
      code: 'name.toBuilder().setFirstName(name.firstName.plus("-hello")).setLastName(name.lastName.plus("-world")).build()'
    }
  }
}

