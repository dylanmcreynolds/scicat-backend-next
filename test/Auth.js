/* eslint-disable @typescript-eslint/no-var-requires */

var accessToken = null;

describe("0100: Authorization functionalities", () => {
  it("0010: Ingestor login fails with incorrect credentials", async () => {
    return request(appUrl)
      .post("/api/v3/auth/login")
      .send({
        username: "ingestor",
        password: "asd123",
      })
      .set("Accept", "application/json")
      .then((res) => {
        res.should.have.property("error");
      });
  });

  it("0020: Logout with unauthenticated user should fail", async () => {
    return request(appUrl)
      .post("/api/v3/auth/logout")
      .set("Accept", "application/json")
      .expect(401);
  });

  it("0030: Login should succeed with correct credentials", async () => {
    return request(appUrl)
      .post("/api/v3/auth/login")
      .send({
        username: "ingestor",
        password: "aman",
      })
      .set("Accept", "application/json")
      .expect(201)
      .expect("Content-Type", /json/)
      .then((res) => {
        res.body.should.have.property("user").and.be.instanceof(Object);
        accessToken = res.body.id;
      });
  });

  it("0040: Logout with authenticated user should succeed", async () => {
    return request(appUrl)
      .post("/api/v3/auth/logout")
      .set("Accept", "application/json")
      .set({ Authorization: `Bearer ${accessToken}` })
      .expect(200);
  });
});
