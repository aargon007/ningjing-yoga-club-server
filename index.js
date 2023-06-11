const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const app = express();
const port = process.env.PORT || 5000;
const jwt = require("jsonwebtoken");

// middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
	const authorization = req.headers.authorization;
	if (!authorization) {
		return res
			.status(401)
			.send({ error: true, message: "unauthorized access" });
	}
	// bearer token
	const token = authorization.split(" ")[1];

	jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
		if (error) {
			return res
				.status(401)
				.send({ error: true, message: "unauthorized access" });
		}
		req.decoded = decoded;
		next();
	});
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.njwxpap.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true,
	},
	useNewUrlParser: true,
	useUnifiedTopology: true,
	maxPoolSize: 60,
});

async function run() {
	try {
		// Connect the client to the server	(optional starting in v4.7)
		await client.connect();

		//db pool
		const usersCollection = client.db("yogaMeditation").collection("users");
		const classCollection = client.db("yogaMeditation").collection("classes");
		const selectedClassCollection = client
			.db("yogaMeditation")
			.collection("selectedClass");
		const enrolledClassCollection = client
			.db("yogaMeditation")
			.collection("enrolledClass");

		//jwt token
		app.post("/jwt", (req, res) => {
			const user = req.body;
			const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
				expiresIn: "5h",
			});

			res.send({ token });
		});

		const verifyAdmin = async (req, res, next) => {
			const email = req.decoded.email;
			const query = { email: email };
			const user = await usersCollection.findOne(query);
			if (user?.role !== "admin") {
				return res
					.status(403)
					.send({ error: true, message: "forbidden message" });
			}
			next();
		};

		//read user info for admin only
		app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
			const result = await usersCollection.find().toArray();
			res.send(result);
		});

		//get only instructors data for public user
		app.get("/allInstructors", async (req, res) => {
			const result = await usersCollection
				.find({ role: "instructor" })
				.sort({ createdAt: -1 })
				.toArray();
			res.send(result);
		});

		//read single users data
		app.get("/users/:email", verifyJWT, async (req, res) => {
			const email = req.params.email;
			const decodedEmail = req.decoded.email;
			if (email !== decodedEmail) {
				return res
					.status(403)
					.send({ error: true, message: "unauthorized access" });
			}
			const query = { email: email };
			const result = await usersCollection.findOne(query);
			res.send(result);
		});

		//check if user is admin
		app.get("/users/admin/:email", verifyJWT, async (req, res) => {
			const email = req.params.email;

			if (req.decoded.email !== email) {
				res.send({ admin: false });
			}

			const query = { email: email };
			const user = await usersCollection.findOne(query);
			const result = { admin: user?.role === "admin" };
			res.send(result);
		});

		//check if user is Instructor
		app.get("/users/instructor/:email", verifyJWT, async (req, res) => {
			const email = req.params.email;

			if (req.decoded.email !== email) {
				res.send({ instructor: false });
			}

			const query = { email: email };
			const user = await usersCollection.findOne(query);
			const result = { instructor: user?.role === "instructor" };
			res.send(result);
		});

		//add users info in db for all users
		app.post("/users", async (req, res) => {
			const user = req.body;
			user.createdAt = new Date();
			const query = { email: user.email };
			const existingUser = await usersCollection.findOne(query);

			if (existingUser) {
				return res.send({ message: "user already exists" });
			}

			const result = await usersCollection.insertOne(user);
			res.send(result);
		});

		//update single user info
		app.patch("/users/:id", verifyJWT, async (req, res) => {
			const id = req.params.id;
			const body = req.body;

			const filter = { _id: new ObjectId(id) };

			const updateUser = {
				$set: {
					photo: body.photo,
					name: body.name,
					phone: body.phone,
					address: body.address,
					gender: body.gender,
				},
			};

			const result = await usersCollection.updateOne(filter, updateUser);
			res.send(result);
		});

		//update role for admin only
		app.patch("/users/admin/:id", verifyJWT, verifyAdmin, async (req, res) => {
			const id = req.params.id;
			const body = req.body;
			const filter = { _id: new ObjectId(id) };
			const updateUser = {
				$set: {
					role: body.role,
				},
			};
			const result = await usersCollection.updateOne(filter, updateUser);
			res.send(result);
		});

		//get all classes for admin
		app.get("/classes", verifyJWT, verifyAdmin, async (req, res) => {
			const result = await classCollection
				.find()
				.sort({ createdAt: -1 })
				.toArray();
			res.send(result);
		});

		// get class data for instructor
		app.get("/classes/instructor/:email", verifyJWT, async (req, res) => {
			const email = req.params.email;

			if (!email) {
				res.send([]);
			}

			const decodedEmail = req.decoded.email;
			if (email !== decodedEmail) {
				return res
					.status(403)
					.send({ error: true, message: "forbidden access" });
			}

			const query = { email: email };
			const result = await classCollection.find(query).toArray();
			res.send(result);
		});

		//get approved class for public
		app.get("/publicClasses", async (req, res) => {
			const result = await classCollection
				.find({ status: "approved" })
				.sort({ createdAt: -1 })
				.toArray();
			res.send(result);
		});

		//add class -- instructor only
		app.post("/classes", verifyJWT, async (req, res) => {
			const classItem = req.body;
			classItem.createdAt = new Date();
			const result = await classCollection.insertOne(classItem);
			res.send(result);
		});

		//update class data -- instructor only
		app.patch("/classes/instructor/:id", verifyJWT, async (req, res) => {
			const id = req.params.id;
			const body = req.body;
			const filter = { _id: new ObjectId(id) };
			const updateClass = {
				$set: {
					name: body.name,
					image: body.image,
					seats: body.seats,
					price: body.price,
				},
			};
			const result = await classCollection.updateOne(filter, updateClass);
			res.send(result);
		});

		//update class status -- admin only
		app.patch(
			"/classes/admin/:id",
			verifyJWT,
			verifyAdmin,
			async (req, res) => {
				const id = req.params.id;
				const body = req.body;
				const filter = { _id: new ObjectId(id) };
				const updateStatus = {
					$set: {
						status: body.status,
					},
				};
				const result = await classCollection.updateOne(filter, updateStatus);
				res.send(result);
			}
		);

		//update feedback - admin only
		app.patch(
			"/classes/feedback/:id",
			verifyJWT,
			verifyAdmin,
			async (req, res) => {
				const id = req.params.id;
				const body = req.body;

				const filter = { _id: new ObjectId(id) };
				const updateFeedback = {
					$set: {
						feedback: body.feedback,
					},
				};

				const result = await classCollection.updateOne(filter, updateFeedback);
				res.send(result);
			}
		);

		//get selected classes for student
		app.get("/selectedClasses/:email", verifyJWT, async (req, res) => {
			const email = req.params.email;

			if (!email) {
				res.send([]);
			}

			const decodedEmail = req.decoded.email;
			if (email !== decodedEmail) {
				return res
					.status(403)
					.send({ error: true, message: "forbidden access" });
			}

			const query = { studentEmail: email };
			const result = await selectedClassCollection
				.find(query)
				.sort({ createdAt: -1 })
				.toArray();
			res.send(result);
		});

		//selected class for student
		app.post("/selectedClasses", verifyJWT, async (req, res) => {
			const selectItem = req.body;
			selectItem.createdAt = new Date();
			const result = await selectedClassCollection.insertOne(selectItem);
			res.send(result);
		});

		//delete an selected class
		app.delete("/selectedClasses/:id", async (req, res) => {
			const id = req.params.id;
			const deleteItem = { _id: new ObjectId(id) };
			const result = await selectedClassCollection.deleteOne(deleteItem);
			res.send(result);
		});

		// create payment intent
		app.post("/create-payment-intent", verifyJWT, async (req, res) => {
			const { price } = req.body;
            const amount = parseInt(price)*100
			const paymentIntent = await stripe.paymentIntents.create({
				amount: amount,
				currency: "usd",
				payment_method_types: ["card"],
			});

			res.send({
				clientSecret: paymentIntent.client_secret,
			});
		});

		// payment related api
		app.post("/payments", verifyJWT, async (req, res) => {
			const payment = req.body;
            payment.createdAt = new Date();
            // console.log(payment);
			const insertResult = await enrolledClassCollection.insertOne(payment);

			const seletedId = {
				_id: new ObjectId(payment?.selectedId),
			};
			const deleteResult = await selectedClassCollection.deleteOne(seletedId);

            const classId = { _id: new ObjectId(payment?.classId) };
			const updateSeats = {
				$inc: {
					seats: -1,
                    enrolled : +1
				},
			};
			const updateResult = await classCollection.updateOne(classId, updateSeats);

			res.send({ insertResult, deleteResult, updateResult });
		});

		// Send a ping to confirm a successful connection
		await client.db("admin").command({ ping: 1 });
		console.log(
			"Pinged your deployment. You successfully connected to MongoDB!"
		);
	} finally {
		// Ensures that the client will close when you finish/error
		// await client.close();
	}
}
run().catch(console.dir);

app.get("/", (req, res) => {
	res.send("server is running");
});

app.listen(port, () => {
	console.log(`server is running on port ${port}`);
});
