const contract = {
  participants: ["owner"],
  scopeSpec: "com.figure.helloWorld",
  functions: [
    {
      name: "name",
      participant: "OWNER",
      inputs: [
        {
          name: "name",
          type: "ExampleName",
        },
      ],
      outputs: [
        {
          type: "ExampleName",
        },
      ],
      body: {
        lang: "kotlin",
        code: 'name.toBuilder().setFirstName(name.firstName.plus("-hello")).setLastName(name.lastName.plus("-world")).build()',
      },
    },
  ],
};
