import { comparePassword, hashPassword } from "../helpers/authHelper.js";
import User from "../models/userModel.js";
import JWT from "jsonwebtoken";

export const registerController = async (req, res) => {
  try {
    const { name, email, password, phone, address, answer } = req.body;
    //validation
    if (!name) {
      return res.send({
        message: "Tên là bắt buộc",
      });
    }
    if (!email) {
      return res.send({
        message: "Email là bắt buộc",
      });
    }
    if (!password) {
      return res.send({
        message: "Mật khẩu là bắt buộc",
      });
    }
    if (!phone) {
      return res.send({
        message: "Số điện thoại là bắt buộc",
      });
    }
    if (!address) {
      return res.send({
        error: "Địa chỉ là bắt buộc",
      });
    }
    if (!answer) {
      return res.send({
        error: "câu trả lời là bắt buộc",
      });
    }

    //check user
    const exisitingUser = await User.findOne({ email });
    //existing user
    if (exisitingUser) {
      return res.status(200).send({
        success: false,
        message: "Email của bạn đã tồn tại vui lòng sử dụng email khác!",
      });
    }

    //register user
    const hashedPassword = await hashPassword(password);
    //save
    const user = new User({
      name,
      email,
      phone,
      address,
      password: hashedPassword,
      answer,
    }).save();
    res.status(200).send({
      success: true,
      message: "Bạn đã đăng kí thành công",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: " Lỗi đăng kí",
      error,
    });
  }
};

//POST LOGIN

export const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    //validation
    if (!email || !password) {
      return res.status(404).send({
        success: false,
        message: "Email hoặc mật khẩu không hợp lệ",
      });
    }
    //check user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Email không hợp lệ",
      });
    }

    const match = await comparePassword(password, user.password);
    if (!match) {
      return res.status(200).send({
        success: false,
        message: "Mật khẩu không đúng",
      });
    }

    //token
    const token = await JWT.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.status(200).send({
      success: true,
      message: "Đăng nhập thành công",
      user: {
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address,
      },
      token,
    });
  } catch (error) {
    console.log(error);
    res.status({
      success: false,
      message: "Lỗi khi đăng nhập",
      error,
    });
  }
};

//forgotPasswordController
export const forgotPasswordController = async (req, res) => {
  try {
    const { email, answer, newPassword } = req.body;
    if (!email) {
      res.status(400).send({ message: "Email là bắt buộc" });
    }
    if (!answer) {
      res.status(400).send({ message: "Câu trả lời là bắt buộc" });
    }
    if (!newPassword) {
      res.status(400).send({ message: "Password mới là bắt buộc" });
    }

    //check
    const user = await User.findOne({ email, answer });
    //validation
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Sai email hoặc câu trả lời",
      });
    }
    const hashed = await hashPassword(newPassword);
    await User.findByIdAndUpdate(user._id, { password: hashed });
    res.status(200).send({
      success: true,
      message: "Đặt lại mật khẩu thành công ",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Có gì đó đang sai",
      error,
    });
  }
};

//test controller
export const testController = (req, res) => {
  res.send("Protected");
};
