const express = require("express");
const router = express.Router();
const upload = require("../middleware/mod.upload");
const AzureBlobService = require("../factory/azureBlob");
const AzureKeyFactory = require("../factory/azurekeyVault");
const fs = require("fs");

router.get("/ping", (req, res) => {
	res.status(200).send("pong");
});

router.get("/", (req, res) => {
	const hostname =
		process.env.ENVIRONMENT === "dev"
			? `${req.protocol}://${req.header("host")}`
			: `${req.protocol}://${req.hostname}`;
	res.render("index");
});

router.get("/server", (req, res) => {
	const hostname =
		process.env.ENVIRONMENT === "dev"
			? `${req.protocol}://${req.header("host")}`
			: `${req.protocol}://${req.hostname}`;
	res.render("server2");
});

router.get("/cert", (req, res) => {
	const hostname =
		process.env.ENVIRONMENT === "dev"
			? `${req.protocol}://${req.header("host")}`
			: `${req.protocol}://${req.hostname}`;
	res.render("cert");
});

// Routes
router.post("/upload", upload.single("file"), async (req, res) => {
	console.log(req.body.userid);
	console.log(req.file);

	/*{
	fieldname: 'file',
	originalname: 'Git-2.49.0-64-bit.exe',
	encoding: '7bit',
	mimetype: 'application/x-msdownload',
	destination: 'D:\\Users\\LeeChooYee\\repo\\jsrepo\\pqc-encryption-poc\\uploads',
	filename: 'Git-2.49.0-64-bit-1747132406595-b410660e3bd7ca9c.exe',
	path: 'D:\\Users\\LeeChooYee\\repo\\jsrepo\\pqc-encryption-poc\\uploads\\Git-2.49.0-64-bit-1747132406595-b410660e3bd7ca9c.exe',
	size: 70287136
	}
  	*/

	//==============================================================================
	//Encrypt uploaded file
	//==============================================================================
	const result = await AzureKeyFactory.EncryptFile("test", req.file.path);	
	const encryptedFile = Buffer.from(result.encryptedFile, "base64");
	fs.writeFileSync(req.file.path + ".dat", encryptedFile);

	// const descryptRes = await AzureKeyFactory.DecryptFile("test", result.encryptedSymmetricKey,result.iv, req.file.path + ".dat");
	// const clearFile = Buffer.from(descryptRes, "base64");
	// fs.writeFileSync("./download/" + req.file.filename, clearFile);

	const fsParts = GetFileSizePart(encryptedFile.length);

	let start=0;
	let end =0;
	let i = 0;
	for(part of fsParts)
	{		
		end = end + part.bytesAlloc; 
		console.log(`start: ${start} - end: ${ end}`)
		const fsSlice = encryptedFile.slice(start, end);
		//part.fsSlice.push(fsSlice);
		start = end;
		const fileName = `./download/encrypted_part_${i + 1}.dat`;
		fs.writeFileSync(fileName, fsSlice);
		i++;
	}

	const glue = [];
	for (let x=0;x<i;x++)
	{
		const fileName = `./download/encrypted_part_${x + 1}.dat`;
		glue.push(fs.readFileSync(fileName));
		
	}
	const gluedFile = Buffer.concat(glue);
	const gluedFileName = "./download/gluedfile.dat";
	fs.writeFileSync(gluedFileName, gluedFile);

	descryptRes = await AzureKeyFactory.DecryptFile("test", result.encryptedSymmetricKey,result.iv,gluedFileName);
	fs.writeFileSync("./download/" + req.file.filename,  Buffer.from(descryptRes, "base64"));
	//1. convert encrypted base64 to file
	//2. store the meta data as file
	//3. store the encrypted file to blob
	// const encryptedFile = Buffer.from(result.encryptedFile, "base64");
	// const fileSizeKB = req.file.size / 1024;
	// if (fileSizeKB > 100) {
	// 	// Split the encrypted file buffer into 10 parts
	// 	const parts = [];
	// 	const partLength = Math.ceil(encryptedFile.length / 10);
	// 	for (let i = 0; i < 10; i++) {
	// 		const part = encryptedFile.slice(i * partLength, (i + 1) * partLength);
	// 		parts.push(part);
	// 		// Save each part into a .dat file
	// 		const fileName = `encrypted_part_${i + 1}.dat`;
	// 		fs.writeFileSync(fileName, part);
	// 	}
	// 	console.log(`File size is ${fileSizeKB.toFixed(2)}KB - split into ${parts.length} parts and saved as .dat files.`);
	// 	// Further process each part as needed (e.g., uploading to blob)
	// } else {
	// 	// Save the whole encrypted file if splitting is not necessary
	// 	const fileName = `encrypted_file.dat`;
	// 	fs.writeFileSync(fileName, encryptedFile);
	// 	console.log(`File size is ${fileSizeKB.toFixed(2)}KB - saved entire encrypted file as ${fileName}.`);
	// }
	// console.log(result);
	res.status(200).json(req.file);
});

function getRndInteger(min, max) {
	return Math.floor(Math.random() * (max - min) ) + min;
  }

function GetFileSizePart(totalFileBytes)
{
	console.log(`total file bytes: ${totalFileBytes}`)
	let totalBytesAlloc = 0;
	const parts = [];
	const maxPart = 10;
	let totalPart = maxPart;
	while (totalPart>0)
	{
		console.log(`total file bytes: ${totalBytesAlloc}`)
		const rnd = getRndInteger(1, maxPart);
		console.log(`Part: ${rnd}`)
		const partData = {};

		if (rnd< totalPart)
		{
			const bytesAlloc =  Math.floor(totalFileBytes * (rnd/10));//calculate number of bytes to be slice
			console.log(`bytesAlloc: ${bytesAlloc}`)
			
			partData.bytesAlloc = bytesAlloc;//number of bytes to be slice
			parts.push(partData);
			totalPart = totalPart - rnd;
			totalBytesAlloc+=bytesAlloc;// to track how many bytes allocated
		}
		else{
			const bytesAlloc = totalFileBytes - totalBytesAlloc; //get the last bit of unallocated bytes		
			partData.bytesAlloc = bytesAlloc;//number of bytes to be slice
			parts.push(partData);
			totalPart = 0;
		}
		console.log(`totalPart: ${totalPart}`)
	}
	console.log(parts);
	return parts;
}	

function ChunkFile(encryptedFile)
{
	const chunks = GetFileSizePart(encryptedFile.length);

	let start=0;
	let end =0;
	let i = 0;
	for(chunk of chunks)
	{		
		end = end + chunk.bytesAlloc; 
		console.log(`start: ${start} - end: ${ end}`)
		const fsSlice = encryptedFile.slice(start, end);
		start = end;

		// //random file name
		// const azureBlobService = new AzureBlobService({
		// 	accountName: process.env.AZURE_BLOB_ACCOUNTNAME,
		// 	containerName: process.env.AZURE_BLOB_CONTAINERNAME
		// });
		// await azureBlobService.uploadBlob(`encrypted_part_${i + 1}.dat`, fsSlice);
		const fileName = `./download/encrypted_part_${i + 1}.dat`;
		fs.writeFileSync(fileName, fsSlice);
		i++;
	}
}

module.exports = router;

/*
	const options = {"accountName":process.env.AZURE_BLOB_ACCOUNTNAME, "containerName":process.env.AZURE_BLOB_CONTAINERNAME};
	// console.log(options)
	const blob = new AzureBlobService(options);
	// blob.uploadBlob(req.file.originalname, req.file.buffer);
	const blobContent = await blob.listBlobs();
	console.log(blobContent)
*/ 